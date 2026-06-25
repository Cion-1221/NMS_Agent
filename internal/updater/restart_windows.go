//go:build windows

package updater

import "os"

// restart exits cleanly so the Windows Service Control Manager can restart
// the agent with the newly installed binary.
func restart(_ string) error {
	os.Exit(0)
	return nil
}
