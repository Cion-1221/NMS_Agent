//go:build !windows

package updater

import (
	"os"
	"syscall"
)

// restart replaces the current process image with the new binary via execve.
// The PID stays the same; systemd sees no restart event.
func restart(exe string) error {
	return syscall.Exec(exe, append([]string{exe}, os.Args[1:]...), os.Environ())
}
