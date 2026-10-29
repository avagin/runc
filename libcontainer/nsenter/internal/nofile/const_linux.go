//go:build !mips && !mipsle && !mips64 && !mips64le && !sparc64

package nofile

const rlimitNofile = 0x7
