package sys

import (
	"errors"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

func startDetached(exe string) error {
	flags := uint32(windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_BREAKAWAY_FROM_JOB)
	err := spawnDetached(exe, flags)
	// Un job sin JOB_OBJECT_LIMIT_BREAKAWAY_OK niega el breakaway: se reintenta una vez sin él.
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		err = spawnDetached(exe, flags&^windows.CREATE_BREAKAWAY_FROM_JOB)
	}
	return err
}

// spawnDetached: sin stdin, stdout ni stderr heredados; Dir es la carpeta del exe para no dejar abierta la carpeta actual
// del llamador (un USB no se podría expulsar).
func spawnDetached(exe string, flags uint32) error {
	cmd := exec.Command(exe)
	cmd.Dir = filepath.Dir(exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
