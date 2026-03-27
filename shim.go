package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func setupShim(targetPath string) error {
	// Get shimmer executable path
	shimmerPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get shimmer path: %w", err)
	}

	// Resolve target to absolute path
	absTargetPath, err := exec.LookPath(targetPath)
	if err != nil {
		return fmt.Errorf("failed to find program '%s': %w", targetPath, err)
	}

	// Create the -real.exe backup name
	dir := filepath.Dir(absTargetPath)
	base := filepath.Base(absTargetPath)
	ext := filepath.Ext(base)
	nameWithoutExt := strings.TrimSuffix(base, ext)
	realPath := filepath.Join(dir, nameWithoutExt+"-real"+ext)

	// Check if already shimmed
	if _, err := os.Stat(realPath); err == nil {
		return fmt.Errorf("program already shimmed: %s exists", realPath)
	}

	logMsg("Setting up shim for %s", targetPath)

	// Rename original to -real
	if err := os.Rename(absTargetPath, realPath); err != nil {
		return fmt.Errorf("failed to rename original: %w", err)
	}

	// Copy shimmer to original location
	shimmerData, err := os.ReadFile(shimmerPath)
	if err != nil {
		// Restore original on error
		os.Rename(realPath, absTargetPath)
		return fmt.Errorf("failed to read shimmer: %w", err)
	}

	if err := os.WriteFile(absTargetPath, shimmerData, 0755); err != nil {
		// Restore original on error
		os.Rename(realPath, absTargetPath)
		return fmt.Errorf("failed to write shim: %w", err)
	}

	logMsg("Successfully shimmed %s -> %s", absTargetPath, realPath)
	return nil
}

func unshim(targetPath string) error {
	// Resolve target to absolute path
	absTargetPath, err := exec.LookPath(targetPath)
	if err != nil {
		return fmt.Errorf("failed to find program '%s': %w", targetPath, err)
	}

	// Create the -real.exe backup name
	dir := filepath.Dir(absTargetPath)
	base := filepath.Base(absTargetPath)
	ext := filepath.Ext(base)
	nameWithoutExt := strings.TrimSuffix(base, ext)
	realPath := filepath.Join(dir, nameWithoutExt+"-real"+ext)

	// Check if the -real version exists
	if _, err := os.Stat(realPath); os.IsNotExist(err) {
		return fmt.Errorf("program is not shimmed: %s does not exist", realPath)
	}

	logMsg("Removing shim for %s", targetPath)

	// Remove the shim (current executable at absTargetPath)
	if err := os.Remove(absTargetPath); err != nil {
		return fmt.Errorf("failed to remove shim: %w", err)
	}

	// Rename -real back to original
	if err := os.Rename(realPath, absTargetPath); err != nil {
		return fmt.Errorf("failed to restore original: %w", err)
	}

	logMsg("Successfully unshimmed %s", absTargetPath)
	fmt.Printf("Successfully removed shim for %s\n", targetPath)
	return nil
}
