package nsenter

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// Log levels are the same as in logrus.
const (
	levelPanic = iota
	levelFatal
	levelError
	levelWarning
	levelInfo
	levelDebug
	levelTrace
)

var levelStr = [...]string{"panic", "fatal", "error", "warning", "info", "debug", "trace"}

var (
	logFd    = -1
	logLevel = levelDebug
	logStage = "nsexec"
)

// envInt returns the value of the environment variable as a non-negative
// integer, or -1 if it is not set (or empty).
func envInt(name string) int {
	val := os.Getenv(name)
	// Treat empty value as unset variable.
	if val == "" {
		return -1
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		bail("unable to parse %s=%s", name, val)
	}
	// Sanity check: this must be a non-negative number.
	if i < 0 {
		bail("bad value for %s=%s (%d)", name, val, i)
	}
	return i
}

// setupLog sets up logging by getting log fd and log level from the
// environment, if available.
func setupLog() {
	fd := envInt("_LIBCONTAINER_LOGPIPE")
	if fd < 0 {
		// We are not runc init, or log pipe was not provided.
		return
	}
	logFd = fd
	if level := envInt("_LIBCONTAINER_LOGLEVEL"); level >= 0 {
		logLevel = level
	}
}

func setStage(stage string) {
	logStage = stage
}

func logEnabledFor(level int) bool {
	return logFd >= 0 && level <= logLevel
}

func writeLog(level int, format string, args ...any) {
	if !logEnabledFor(level) || level >= len(levelStr) {
		return
	}
	msg := fmt.Sprintf("%s[%d]: %s", logStage, os.Getpid(), fmt.Sprintf(format, args...))
	data, err := json.Marshal(struct {
		Level string `json:"level"`
		Msg   string `json:"msg"`
	}{levelStr[level], msg})
	if err != nil {
		return
	}
	// This logging is on a best-effort basis. In case of a short or failed
	// write there is nothing we can do, so just ignore write() errors.
	_ = writeAll(logFd, append(data, '\n'))
}

func logDebug(format string, args ...any) {
	writeLog(levelDebug, format, args...)
}

// bail logs a message to the log pipe (or stderr, if it is not available)
// and terminates the program.
func bail(format string, args ...any) {
	if logFd < 0 {
		fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	} else {
		writeLog(levelFatal, format, args...)
	}
	os.Exit(1)
}
