package libcontainer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/exeseal"
	"github.com/opencontainers/runc/libcontainer/intelrdt"
	"github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runc/libcontainer/utils"
)

const stdioFdCount = 3

// Container is a libcontainer container object.
type Container struct {
	id                   string
	stateDir             string
	config               *configs.Config
	cgroupManager        cgroups.Manager
	intelRdtManager      *intelrdt.Manager
	initProcess          parentProcess
	initProcessStartTime uint64
	m                    sync.Mutex
	criuVersion          int
	state                containerState
	created              time.Time
	fifo                 *os.File
}

// State represents a running container's state
type State struct {
	BaseState

	// Platform specific fields below.

	// Specified if the container was started under the rootless mode.
	// Set to true if BaseState.Config.RootlessEUID && BaseState.Config.RootlessCgroups
	Rootless bool `json:"rootless,omitempty"`

	// Paths to all the container's cgroups, as returned by (*cgroups.Manager).GetPaths
	//
	// For cgroup v1, a key is cgroup subsystem name, and the value is the path
	// to the cgroup for this subsystem.
	//
	// For cgroup v2 unified hierarchy, a key is "", and the value is the unified path.
	CgroupPaths map[string]string `json:"cgroup_paths,omitempty"`

	// NamespacePaths are filepaths to the container's namespaces. Key is the namespace type
	// with the value as the path.
	NamespacePaths map[configs.NamespaceType]string `json:"namespace_paths"`

	// Container's standard descriptors (std{in,out,err}), needed for checkpoint and restore.
	ExternalDescriptors []string `json:"external_descriptors,omitempty"`

	// Intel RDT "resource control" filesystem path.
	IntelRdtPath string `json:"intel_rdt_path,omitempty"`

	// Path of the container specific monitoring group in resctrl filesystem.
	// Empty if the container does not have aindividual dedicated monitoring
	// group.
	IntelRdtMonPath string `json:"intel_rdt_mon_path,omitempty"`
}

// ID returns the container's unique ID
func (c *Container) ID() string {
	return c.id
}

// Config returns the container's configuration
func (c *Container) Config() configs.Config {
	return *c.config
}

// Status returns the current status of the container.
func (c *Container) Status() (Status, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentStatus()
}

// State returns the current container's state information.
func (c *Container) State() (*State, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentState(), nil
}

// OCIState returns the current container's state information.
func (c *Container) OCIState() (*specs.State, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentOCIState()
}

// ignoreCgroupError filters out cgroup-related errors that can be ignored,
// because the container is stopped and its cgroup is gone.
func (c *Container) ignoreCgroupError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) && !c.hasInit() && !c.cgroupManager.Exists() {
		return nil
	}
	return err
}

// Processes returns the PIDs inside this container. The PIDs are in the
// namespace of the calling process.
//
// Some of the returned PIDs may no longer refer to processes in the container,
// unless the container state is PAUSED in which case every PID in the slice is
// valid.
func (c *Container) Processes() ([]int, error) {
	pids, err := c.cgroupManager.GetAllPids()
	if err = c.ignoreCgroupError(err); err != nil {
		return nil, fmt.Errorf("unable to get all container pids: %w", err)
	}
	return pids, nil
}

// Stats returns statistics for the container.
func (c *Container) Stats() (*Stats, error) {
	var (
		err   error
		stats = &Stats{}
	)
	if stats.CgroupStats, err = c.cgroupManager.GetStats(); err != nil {
		return stats, fmt.Errorf("unable to get container cgroup stats: %w", err)
	}
	if c.intelRdtManager != nil {
		if stats.IntelRdtStats, err = c.intelRdtManager.GetStats(); err != nil {
			return stats, fmt.Errorf("unable to get container Intel RDT stats: %w", err)
		}
	}
	return stats, nil
}

// Set resources of container as configured. Can be used to change resources
// when the container is running.
func (c *Container) Set(config configs.Config) error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	if status == Stopped {
		return ErrNotRunning
	}
	if err := c.cgroupManager.Set(config.Cgroups.Resources); err != nil {
		// Set configs back
		if err2 := c.cgroupManager.Set(c.config.Cgroups.Resources); err2 != nil {
			logrus.Warnf("Setting back cgroup configs failed due to error: %v, your state.json and actual configs might be inconsistent.", err2)
		}
		return err
	}
	if c.intelRdtManager != nil {
		if err := c.intelRdtManager.Set(&config); err != nil {
			// Set configs back
			if err2 := c.cgroupManager.Set(c.config.Cgroups.Resources); err2 != nil {
				logrus.Warnf("Setting back cgroup configs failed due to error: %v, your state.json and actual configs might be inconsistent.", err2)
			}
			if err2 := c.intelRdtManager.Set(c.config); err2 != nil {
				logrus.Warnf("Setting back intelrdt configs failed due to error: %v, your state.json and actual configs might be inconsistent.", err2)
			}
			return err
		}
	}
	// After config setting succeed, update config and states
	c.config = &config
	_, err = c.updateState(nil)
	return err
}

// Start starts a process inside the container. Returns error if process fails
// to start. You can track process lifecycle with passed Process structure.
func (c *Container) Start(process *Process) error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.start(process)
}

// Run immediately starts the process inside the container. Returns an error if
// the process fails to start. It does not block waiting for the exec fifo
// after start returns but opens the fifo after start returns.
func (c *Container) Run(process *Process) error {
	c.m.Lock()
	defer c.m.Unlock()
	if err := c.start(process); err != nil {
		return err
	}
	if process.Init {
		return c.exec()
	}
	return nil
}

// Exec signals the container to exec the users process at the end of the init.
func (c *Container) Exec() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.exec()
}

func (c *Container) exec() error {
	path := filepath.Join(c.stateDir, execFifoFilename)
	if err := handleFifo(path, c.initProcess.pid()); err != nil {
		return err
	}

	return c.postStart()
}

// handleFifo listens for either a byte written to the FIFO file or
// the init process exiting. On kernels supporting pidfd_open(2)
// (>= 5.3), it uses a single poll(2) for efficiency. On older kernels,
// it falls back to a polling loop that periodically checks the init
// process's liveness. This function is blocking.
func handleFifo(path string, pid int) error {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("exec fifo: %w", err)
	}
	defer f.Close()

	if err := waitForFifoReady(f, pid); err != nil {
		return err
	}

	if err := readFromExecFifo(f); err != nil {
		return err
	}

	if err := os.Remove(f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// waitForFifoReady blocks until either the FIFO has data available to read,
// or the init process has exited. It does not consume the data — it only
// returns once a subsequent read on f will not block indefinitely.
func waitForFifoReady(f *os.File, pid int) error {
	// TODO: switch to os.Process.WithHandle once go < 1.26 is no longer supported.
	pidFd, err := unix.PidfdOpen(pid, 0)
	if err == nil {
		defer unix.Close(pidFd)
		return waitForFifoReadyPidfd(f, pidFd)
	}
	// fall through to the polling path.
	return waitForFifoReadyPolling(f, pid)
}

// fast path: a single poll(2) on both the
// FIFO and a pidfd, blocking with no timeout.
func waitForFifoReadyPidfd(f *os.File, pidFd int) error {
	pfds := []unix.PollFd{
		{Fd: int32(f.Fd()), Events: unix.POLLIN},
		{Fd: int32(pidFd), Events: unix.POLLIN},
	}
	for {
		_, err := unix.Poll(pfds, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll exec fifo: %w", err)
		}
		// We don't care which FD woke us up. In all cases the next step
		// is to read the FIFO: if init wrote the byte (alive or dead),
		// it's there to be read; if init died without writing, the read
		// returns EOF and readFromExecFifo reports the dead-process error.
		return nil
	}
}

// the fallback for kernels without pidfd_open.
func waitForFifoReadyPolling(f *os.File, pid int) error {
	pfd := []unix.PollFd{{Fd: int32(f.Fd()), Events: unix.POLLIN}}
	const pollIntervalMs = 100
	for {
		n, err := unix.Poll(pfd, pollIntervalMs)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll exec fifo: %w", err)
		}
		if n > 0 && pfd[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			return nil
		}
		// If init is dead, fallthrough and let readFromExecFifo distinguish
		// "wrote before dying" from "died before writing".
		stat, err := system.Stat(pid)
		if err != nil || stat.State == system.Zombie {
			return nil
		}
	}
}

func readFromExecFifo(execFifo io.Reader) error {
	var buf [1]byte
	n, err := execFifo.Read(buf[:])
	if err != nil && err != io.EOF {
		return fmt.Errorf("read exec fifo: %w", err)
	}
	if n == 0 {
		return errors.New("exec fifo is empty: container init did not signal execve readiness (process died before writing, or fifo already consumed)")
	}
	return nil
}

func (c *Container) postStart() (retErr error) {
	if !c.config.HasHook(configs.Poststart) {
		return nil
	}

	defer func() {
		if retErr != nil {
			// A poststart hook failed; kill the container.
			if err := c.signal(unix.SIGKILL); err != nil && !errors.Is(err, ErrNotRunning) {
				logrus.WithError(err).Warn("kill after failed poststart")
			}
			// We're still init's parent so wait is required.
			_, _ = c.initProcess.wait()
		}
	}()

	s, err := c.currentOCIState()
	if err != nil {
		return err
	}
	return c.config.Hooks.Run(configs.Poststart, s)
}

func (c *Container) start(process *Process) (retErr error) {
	if c.config.Cgroups.Resources.SkipDevices {
		return errors.New("can't start container with SkipDevices set")
	}

	if c.config.RootlessEUID && len(process.AdditionalGroups) > 0 {
		// We cannot set any additional groups in a rootless container
		// and thus we bail if the user asked us to do so.
		return errors.New("cannot set any additional groups in a rootless container")
	}

	if process.Init {
		if c.initProcessStartTime != 0 {
			return errors.New("container already has init process")
		}
		if err := c.createExecFifo(); err != nil {
			return err
		}
		defer func() {
			if retErr != nil {
				c.deleteExecFifo()
			}
		}()
	}

	parent, err := c.newParentProcess(process)
	if err != nil {
		return fmt.Errorf("unable to create new parent process: %w", err)
	}
	// We do not need the cloned binaries once the process is spawned.
	defer process.closeClonedExes()

	// Before starting "runc init", mark all non-stdio open files as O_CLOEXEC
	// to make sure we don't leak any files into "runc init". Any files to be
	// passed to "runc init" through ExtraFiles will get dup2'd by the Go
	// runtime and thus their O_CLOEXEC flag will be cleared. This is some
	// additional protection against attacks like CVE-2024-21626, by making
	// sure we never leak files to "runc init" we didn't intend to.
	if err := utils.CloseExecFrom(3); err != nil {
		return fmt.Errorf("unable to mark non-stdio fds as cloexec: %w", err)
	}

	if logsDone := parent.forwardChildLogs(); logsDone != nil {
		defer func() {
			// Wait for log forwarder to finish. This depends on
			// runc init closing the _LIBCONTAINER_LOGPIPE log fd.
			err := <-logsDone
			if err != nil {
				// runc init errors are important; make sure retErr has them.
				err = fmt.Errorf("runc init error(s): %w", err)
				if retErr != nil {
					retErr = fmt.Errorf("%w; %w", retErr, err)
				} else {
					retErr = err
				}
			}
		}()
	}

	if err := parent.start(); err != nil {
		return fmt.Errorf("unable to start container process: %w", err)
	}

	if process.Init {
		c.fifo.Close()
	}
	return nil
}

// Signal sends a specified signal to container's init.
//
// When s is SIGKILL and the container does not have its own PID namespace, all
// the container's processes are killed. In this scenario, the libcontainer
// user may be required to implement a proper child reaper.
func (c *Container) Signal(s os.Signal) error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.signal(s)
}

func (c *Container) signal(s os.Signal) error {
	// When a container has its own PID namespace, inside it the init PID
	// is 1, and thus it is handled specially by the kernel. In particular,
	// killing init with SIGKILL from an ancestor namespace will also kill
	// all other processes in that PID namespace (see pid_namespaces(7)).
	//
	// OTOH, if PID namespace is shared, we should kill all pids to avoid
	// leftover processes. Handle this special case here.
	if s == unix.SIGKILL && !c.config.Namespaces.IsPrivate(configs.NEWPID) {
		if err := signalAllProcesses(c.cgroupManager, unix.SIGKILL); err != nil {
			if c.config.RootlessCgroups { // may not have an access to cgroup
				logrus.WithError(err).Warn("failed to kill all processes, possibly due to lack of cgroup (Hint: enable cgroup v2 delegation)")
				// Some processes may leak when cgroup is not delegated
				// https://github.com/opencontainers/runc/pull/4395#pullrequestreview-2291179652
				return c.signalInit(s)
			}
			// For not rootless container, if there is no init process and no cgroup,
			// it means that the container is not running.
			if errors.Is(err, ErrCgroupNotExist) && !c.hasInit() {
				err = ErrNotRunning
			}
			return fmt.Errorf("unable to kill all processes: %w", err)
		}
		return nil
	}

	return c.signalInit(s)
}

func (c *Container) signalInit(s os.Signal) error {
	// To avoid a PID reuse attack, don't kill non-running container.
	if !c.hasInit() {
		return ErrNotRunning
	}
	if err := c.initProcess.signal(s); err != nil {
		return fmt.Errorf("unable to signal init: %w", err)
	}
	if s == unix.SIGKILL {
		// For cgroup v1, killing a process in a frozen cgroup
		// does nothing until it's thawed. Only thaw the cgroup
		// for SIGKILL.
		if paused, _ := c.isPaused(); paused {
			_ = c.cgroupManager.Freeze(cgroups.Thawed)
		}
	}
	return nil
}

func (c *Container) createExecFifo() (retErr error) {
	rootuid, err := c.config.HostRootUID()
	if err != nil {
		return err
	}
	rootgid, err := c.config.HostRootGID()
	if err != nil {
		return err
	}

	fifoName := filepath.Join(c.stateDir, execFifoFilename)
	if err := unix.Mkfifo(fifoName, 0o622); err != nil {
		return &os.PathError{Op: "mkfifo", Path: fifoName, Err: err}
	}
	defer func() {
		if retErr != nil {
			os.Remove(fifoName)
		}
	}()
	// Ensure permission bits (can be different because of umask).
	if err := os.Chmod(fifoName, 0o622); err != nil {
		return err
	}
	return os.Chown(fifoName, rootuid, rootgid)
}

func (c *Container) deleteExecFifo() {
	fifoName := filepath.Join(c.stateDir, execFifoFilename)
	os.Remove(fifoName)
}

// includeExecFifo opens the container's execfifo as a pathfd, so that the
// container cannot access the statedir (and the FIFO itself remains
// un-opened). It then adds the FifoFd to the given nsenter.Config as an
// inherited fd, with _LIBCONTAINER_FIFOFD set to its fd number.
func (c *Container) includeExecFifo(cfg *nsenter.Config) error {
	fifoName := filepath.Join(c.stateDir, execFifoFilename)
	fifo, err := os.OpenFile(fifoName, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	c.fifo = fifo

	cfg.ExtraFiles = append(cfg.ExtraFiles, fifo)
	cfg.Env = append(cfg.Env,
		"_LIBCONTAINER_FIFOFD="+strconv.Itoa(stdioFdCount+len(cfg.ExtraFiles)-1))
	return nil
}

func (c *Container) newParentProcess(p *Process) (parentProcess, error) {
	comm, err := newProcessComm()
	if err != nil {
		return nil, err
	}

	// Make sure we use a new safe copy of /proc/self/exe binary each time, this
	// is called to make sure that if a container manages to overwrite the file,
	// it cannot affect other containers on the system. For runc, this code will
	// only ever be called once, but libcontainer users might call this more than
	// once.
	p.closeClonedExes()
	var safeExe *os.File
	if exeseal.IsSelfExeCloned() {
		// /proc/self/exe is already a cloned binary -- no need to do anything
		logrus.Debug("skipping binary cloning -- /proc/self/exe is already cloned!")
	} else {
		var err error
		safeExe, err = exeseal.CloneSelfExe(c.stateDir)
		if err != nil {
			return nil, fmt.Errorf("unable to create safe /proc/self/exe clone for runc init: %w", err)
		}
		p.clonedExes = append(p.clonedExes, safeExe)
		logrus.Debug("runc exeseal: using /proc/self/exe clone") // used for tests
	}

	var cfg nsenter.Config
	cfg.Exe = safeExe
	cfg.Args = []string{os.Args[0], "init"}
	cfg.Dir = c.config.Rootfs
	cfg.Env = append(os.Environ(), "GOMAXPROCS="+os.Getenv("GOMAXPROCS"))
	cfg.ExtraFiles = append(cfg.ExtraFiles, p.ExtraFiles...)

	addExtraFile := func(f *os.File, envName string) {
		cfg.ExtraFiles = append(cfg.ExtraFiles, f)
		cfg.Env = append(cfg.Env,
			envName+"="+strconv.Itoa(stdioFdCount+len(cfg.ExtraFiles)-1),
		)
	}
	if p.ConsoleSocket != nil {
		addExtraFile(p.ConsoleSocket, "_LIBCONTAINER_CONSOLE")
	}
	addExtraFile(comm.initSockChild, "_LIBCONTAINER_INITPIPE")
	addExtraFile(comm.syncSockChild.File(), "_LIBCONTAINER_SYNCPIPE")
	addExtraFile(comm.logPipeChild, "_LIBCONTAINER_LOGPIPE")
	if p.LogLevel != "" {
		cfg.Env = append(cfg.Env, "_LIBCONTAINER_LOGLEVEL="+p.LogLevel)
	}
	if p.PidfdSocket != nil {
		addExtraFile(p.PidfdSocket, "_LIBCONTAINER_PIDFD_SOCK")
	}

	// NOTE: when running a container with no PID namespace and the parent
	//       process spawning the container is PID1 the pdeathsig is being
	//       delivered to the container's init process by the kernel for some
	//       reason even with the parent still running.
	if c.config.ParentDeathSignal > 0 {
		cfg.Pdeathsig = unix.Signal(c.config.ParentDeathSignal)
	}

	if p.Init {
		// We only set up fifoFd if we're not doing a `runc exec`. The historic
		// reason for this is that previously we would pass a dirfd that allowed
		// for container rootfs escape (and not doing it in `runc exec` avoided
		// that problem), but we no longer do that. However, there's no need to do
		// this for `runc exec` so we just keep it this way to be safe.
		if err := c.includeExecFifo(&cfg); err != nil {
			return nil, fmt.Errorf("unable to setup exec fifo: %w", err)
		}
		return c.newInitProcess(p, &cfg, comm)
	}
	return c.newSetnsProcess(p, &cfg, comm)
}

func (c *Container) newInitProcess(p *Process, cfg *nsenter.Config, comm *processComm) (*initProcess, error) {
	cfg.Env = append(cfg.Env, "_LIBCONTAINER_INITTYPE="+string(initStandard))
	nsMaps := make(map[configs.NamespaceType]string)
	for _, ns := range c.config.Namespaces {
		if ns.Path != "" {
			nsMaps[ns.Type] = ns.Path
		}
	}
	if err := c.setupNsenter(cfg, c.config.Namespaces.CloneFlags(), nsMaps); err != nil {
		return nil, err
	}

	init := &initProcess{
		containerProcess: containerProcess{
			nsenterCfg: *cfg,
			comm:       comm,
			manager:    c.cgroupManager,
			config:     c.newInitConfig(p),
			process:    p,
			container:  c,
		},
		intelRdtManager: c.intelRdtManager,
	}
	c.initProcess = init
	return init, nil
}

func (c *Container) newSetnsProcess(p *Process, cfg *nsenter.Config, comm *processComm) (*setnsProcess, error) {
	cfg.Env = append(cfg.Env, "_LIBCONTAINER_INITTYPE="+string(initSetns))
	state := c.currentState()
	// for setns process, we don't have to set cloneflags as the process namespaces
	// will only be set via setns syscall
	if err := c.setupNsenter(cfg, 0, state.NamespacePaths); err != nil {
		return nil, err
	}
	proc := &setnsProcess{
		containerProcess: containerProcess{
			nsenterCfg: *cfg,
			comm:       comm,
			manager:    c.cgroupManager,
			config:     c.newInitConfig(p),
			process:    p,
			container:  c,
		},
		rootlessCgroups: c.config.RootlessCgroups,
		intelRdtPath:    state.IntelRdtPath,
		initProcessPid:  state.InitProcessPid,
	}
	return proc, nil
}

func (c *Container) newInitConfig(process *Process) *initConfig {
	// Set initial properties. For those properties that exist
	// both in the container config and the process, use the ones
	// from the container config first, and override them later.
	cfg := &initConfig{
		Config:           c.config,
		Args:             process.Args,
		Env:              process.Env,
		UID:              process.UID,
		GID:              process.GID,
		AdditionalGroups: process.AdditionalGroups,
		Cwd:              process.Cwd,
		Capabilities:     c.config.Capabilities,
		PassedFilesCount: len(process.ExtraFiles),
		ContainerID:      c.ID(),
		NoNewPrivileges:  c.config.NoNewPrivileges,
		AppArmorProfile:  c.config.AppArmorProfile,
		ProcessLabel:     c.config.ProcessLabel,
		Rlimits:          c.config.Rlimits,
		IOPriority:       c.config.IOPriority,
		Scheduler:        c.config.Scheduler,
		CPUAffinity:      c.config.ExecCPUAffinity,
		CreateConsole:    process.ConsoleSocket != nil,
		ConsoleWidth:     process.ConsoleWidth,
		ConsoleHeight:    process.ConsoleHeight,
	}

	// Overwrite config properties with ones from process.

	if process.Capabilities != nil {
		cfg.Capabilities = process.Capabilities
	}
	if process.NoNewPrivileges != nil {
		cfg.NoNewPrivileges = *process.NoNewPrivileges
	}
	if process.AppArmorProfile != "" {
		cfg.AppArmorProfile = process.AppArmorProfile
	}
	if process.Label != "" {
		cfg.ProcessLabel = process.Label
	}
	if len(process.Rlimits) > 0 {
		cfg.Rlimits = process.Rlimits
	}
	if process.IOPriority != nil {
		cfg.IOPriority = process.IOPriority
	}
	if process.Scheduler != nil {
		cfg.Scheduler = process.Scheduler
	}
	if process.CPUAffinity != nil {
		cfg.CPUAffinity = process.CPUAffinity
	}

	// Set misc properties.

	if cgroups.IsCgroup2UnifiedMode() {
		cfg.Cgroup2Path = c.cgroupManager.Path("")
	}

	return cfg
}

// Destroy destroys the container, if its in a valid state.
//
// Any event registrations are removed before the container is destroyed.
// No error is returned if the container is already destroyed.
//
// Running containers must first be stopped using Signal.
// Paused containers must first be resumed using Resume.
func (c *Container) Destroy() error {
	c.m.Lock()
	defer c.m.Unlock()
	if err := c.state.destroy(); err != nil {
		return fmt.Errorf("unable to destroy container: %w", err)
	}
	return nil
}

// Pause pauses the container, if its state is RUNNING or CREATED, changing
// its state to PAUSED. If the state is already PAUSED, does nothing.
func (c *Container) Pause() error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	switch status {
	case Running, Created:
		if err := c.cgroupManager.Freeze(cgroups.Frozen); err != nil {
			return err
		}
		return c.state.transition(&pausedState{
			c: c,
		})
	}
	return ErrNotRunning
}

// Resume resumes the execution of any user processes in the
// container before setting the container state to RUNNING.
// This is only performed if the current state is PAUSED.
// If the Container state is RUNNING, does nothing.
func (c *Container) Resume() error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	if status != Paused {
		return ErrNotPaused
	}
	if err := c.cgroupManager.Freeze(cgroups.Thawed); err != nil {
		return err
	}
	return c.state.transition(&runningState{
		c: c,
	})
}

// NotifyOOM returns a read-only channel signaling when the container receives
// an OOM notification.
func (c *Container) NotifyOOM() (<-chan struct{}, error) {
	// XXX(cyphar): This requires cgroups.
	if c.config.RootlessCgroups {
		logrus.Warn("getting OOM notifications may fail if you don't have the full access to cgroups")
	}
	path := c.cgroupManager.Path("memory")
	if cgroups.IsCgroup2UnifiedMode() {
		return notifyOnOOMV2(path)
	}
	return notifyOnOOM(path)
}

// NotifyMemoryPressure returns a read-only channel signaling when the
// container reaches a given pressure level.
func (c *Container) NotifyMemoryPressure(level PressureLevel) (<-chan struct{}, error) {
	// XXX(cyphar): This requires cgroups.
	if c.config.RootlessCgroups {
		logrus.Warn("getting memory pressure notifications may fail if you don't have the full access to cgroups")
	}
	return notifyMemoryPressure(c.cgroupManager.Path("memory"), level)
}

func (c *Container) updateState(process parentProcess) (*State, error) {
	if process != nil {
		c.initProcess = process
	}
	state := c.currentState()
	if err := c.saveState(state); err != nil {
		return nil, err
	}
	return state, nil
}

func (c *Container) saveState(s *State) (retErr error) {
	tmpFile, err := os.CreateTemp(c.stateDir, "state-")
	if err != nil {
		return err
	}

	defer func() {
		if retErr != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
		}
	}()

	err = utils.WriteJSON(tmpFile, s)
	if err != nil {
		return err
	}
	err = tmpFile.Close()
	if err != nil {
		return err
	}

	stateFilePath := filepath.Join(c.stateDir, stateFilename)
	return os.Rename(tmpFile.Name(), stateFilePath)
}

func (c *Container) currentStatus() (Status, error) {
	if err := c.refreshState(); err != nil {
		return -1, err
	}
	return c.state.status(), nil
}

// refreshState needs to be called to verify that the current state on the
// container is what is true.  Because consumers of libcontainer can use it
// out of process we need to verify the container's status based on runtime
// information and not rely on our in process info.
func (c *Container) refreshState() error {
	paused, err := c.isPaused()
	if err != nil {
		return err
	}
	if paused {
		return c.state.transition(&pausedState{c: c})
	}
	if !c.hasInit() {
		return c.state.transition(&stoppedState{c: c})
	}
	// The presence of exec fifo helps to distinguish between
	// the created and the running states.
	if _, err := os.Stat(filepath.Join(c.stateDir, execFifoFilename)); err == nil {
		return c.state.transition(&createdState{c: c})
	}
	return c.state.transition(&runningState{c: c})
}

// hasInit tells whether the container init process exists.
func (c *Container) hasInit() bool {
	if c.initProcess == nil {
		return false
	}
	pid := c.initProcess.pid()
	stat, err := system.Stat(pid)
	if err != nil {
		return false
	}
	if stat.StartTime != c.initProcessStartTime || stat.State == system.Zombie || stat.State == system.Dead {
		return false
	}
	return true
}

func (c *Container) isPaused() (bool, error) {
	state, err := c.cgroupManager.GetFreezerState()
	if err != nil {
		return false, err
	}
	return state == cgroups.Frozen, nil
}

func (c *Container) currentState() *State {
	var (
		startTime           uint64
		externalDescriptors []string
		pid                 = -1
	)
	if c.initProcess != nil {
		pid = c.initProcess.pid()
		startTime, _ = c.initProcess.startTime()
		externalDescriptors = c.initProcess.externalDescriptors()
	}

	intelRdtPath := ""
	intelRdtMonPath := ""
	if c.intelRdtManager != nil {
		intelRdtPath = c.intelRdtManager.GetPath()
		intelRdtMonPath = c.intelRdtManager.GetMonPath()
	}
	state := &State{
		BaseState: BaseState{
			ID:                   c.ID(),
			Config:               *c.config,
			InitProcessPid:       pid,
			InitProcessStartTime: startTime,
			Created:              c.created,
		},
		Rootless:            c.config.RootlessEUID && c.config.RootlessCgroups,
		CgroupPaths:         c.cgroupManager.GetPaths(),
		IntelRdtPath:        intelRdtPath,
		IntelRdtMonPath:     intelRdtMonPath,
		NamespacePaths:      make(map[configs.NamespaceType]string),
		ExternalDescriptors: externalDescriptors,
	}
	if pid > 0 {
		for _, ns := range c.config.Namespaces {
			state.NamespacePaths[ns.Type] = ns.GetPath(pid)
		}
		for _, nsType := range configs.NamespaceTypes() {
			if !configs.IsNamespaceSupported(nsType) {
				continue
			}
			if _, ok := state.NamespacePaths[nsType]; !ok {
				ns := configs.Namespace{Type: nsType}
				state.NamespacePaths[ns.Type] = ns.GetPath(pid)
			}
		}
	}
	return state
}

func (c *Container) currentOCIState() (*specs.State, error) {
	bundle, annotations := utils.Annotations(c.config.Labels)
	state := &specs.State{
		Version:     specs.Version,
		ID:          c.ID(),
		Bundle:      bundle,
		Annotations: annotations,
	}
	status, err := c.currentStatus()
	if err != nil {
		return nil, err
	}
	state.Status = specs.ContainerState(status.String())
	if status != Stopped {
		if c.initProcess != nil {
			state.Pid = c.initProcess.pid()
		}
	}
	return state, nil
}

// orderNamespacePaths sorts namespace paths into a list of paths that we
// can setns in order.
func (c *Container) orderNamespacePaths(namespaces map[configs.NamespaceType]string) ([]string, error) {
	paths := []string{}
	for _, ns := range configs.NamespaceTypes() {

		// Remove namespaces that we don't need to join.
		if !c.config.Namespaces.Contains(ns) {
			continue
		}

		if p, ok := namespaces[ns]; ok && p != "" {
			// check if the requested namespace is supported
			if !configs.IsNamespaceSupported(ns) {
				return nil, fmt.Errorf("namespace %s is not supported", ns)
			}
			// only set to join this namespace if it exists
			if _, err := os.Lstat(p); err != nil {
				return nil, fmt.Errorf("namespace path: %w", err)
			}
			// do not allow namespace path with comma as we use it to separate
			// the namespace paths
			if strings.ContainsRune(p, ',') {
				return nil, fmt.Errorf("invalid namespace path %s", p)
			}
			paths = append(paths, fmt.Sprintf("%s:%s", configs.NsName(ns), p))
		}

	}

	return paths, nil
}

func encodeIDMapping(idMap []configs.IDMap) string {
	var data strings.Builder
	for _, im := range idMap {
		fmt.Fprintf(&data, "%d %d %d\n", im.ContainerID, im.HostID, im.Size)
	}
	return data.String()
}

// setupNsenter populates the namespace, userns mapping, oom_score_adj, and
// timens offset fields of cfg.
func (c *Container) setupNsenter(cfg *nsenter.Config, cloneFlags uintptr, nsMaps map[configs.NamespaceType]string) error {
	cfg.CloneFlags = cloneFlags

	if len(nsMaps) > 0 {
		nsPaths, err := c.orderNamespacePaths(nsMaps)
		if err != nil {
			return err
		}
		cfg.Namespaces = nsPaths
	}

	// Set userns mappings only when we are not joining an existing user ns.
	_, joinExistingUser := nsMaps[configs.NEWUSER]
	if !joinExistingUser {
		if len(c.config.UIDMappings) > 0 {
			if c.config.RootlessEUID {
				if path, err := exec.LookPath("newuidmap"); err == nil {
					cfg.UIDMapPath = path
				}
			}
			cfg.UIDMap = encodeIDMapping(c.config.UIDMappings)
		}

		if len(c.config.GIDMappings) > 0 {
			cfg.GIDMap = encodeIDMapping(c.config.GIDMappings)
			if c.config.RootlessEUID {
				if path, err := exec.LookPath("newgidmap"); err == nil {
					cfg.GIDMapPath = path
				}
			}
			if requiresRootOrMappingTool(c.config) {
				cfg.Setgroups = true
			}
		}
	}

	cfg.OomScoreAdj = c.config.OomScoreAdj
	cfg.RootlessEUID = c.config.RootlessEUID

	// Write boottime and monotonic time ns offsets only when we are not joining an existing time ns.
	_, joinExistingTime := nsMaps[configs.NEWTIME]
	if !joinExistingTime && c.config.TimeOffsets != nil {
		var offsetSpec bytes.Buffer
		for clock, offset := range c.config.TimeOffsets {
			fmt.Fprintf(&offsetSpec, "%s %d %d\n", clock, offset.Secs, offset.Nanosecs)
		}
		cfg.TimeOffsets = offsetSpec.String()
	}

	return nil
}

// ignoreTerminateErrors returns nil if the given err matches an error known
// to indicate that the terminate occurred successfully or err was nil, otherwise
// err is returned unaltered.
func ignoreTerminateErrors(err error) error {
	if err == nil {
		return nil
	}
	// terminate() might return an error from either Kill or Wait.
	// The (*Cmd).Wait documentation says: "If the command fails to run
	// or doesn't complete successfully, the error is of type *ExitError".
	// Filter out such errors (like "exit status 1" or "signal: killed").
	if _, ok := errors.AsType[*exec.ExitError](err); ok {
		return nil
	}
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	s := err.Error()
	if strings.Contains(s, "Wait was already called") {
		return nil
	}
	return err
}

func requiresRootOrMappingTool(c *configs.Config) bool {
	gidMap := []configs.IDMap{
		{ContainerID: 0, HostID: int64(os.Getegid()), Size: 1},
	}
	return !reflect.DeepEqual(c.GIDMappings, gidMap)
}
