//go:build !windows

package main

import "errors"

func monitorBinary(targetPath string) error {
	return errors.New("monitor command is only supported on Windows")
}
