package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if err := run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	family, err := StartAPD("wlp0s20f0u13")
	if err != nil {
		return fmt.Errorf("failed to resolve nl80211 family: %w", err)
	}
	fmt.Printf("Resolved nl80211 family ID: %d\n", family)

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exeName := filepath.Base(exePath)
	nameWithoutExt := strings.TrimSuffix(exeName, filepath.Ext(exeName))

	if nameWithoutExt == "shmitm" {
		return handleMetaCommands()
	}

	config := LoadConfig()
	compiledConfig, err := CompileConfig(config)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return executeShimmedProgram(exePath, exeName, nameWithoutExt, compiledConfig)
}

func handleMetaCommands() error {
	if len(os.Args) < 2 {
		printUsage()
		return errors.New("no command provided")
	}

	command := os.Args[1]
	switch command {
	case "shim":
		if len(os.Args) < 3 {
			return errors.New("usage: shmitm shim <program>")
		}
		if err := setupShim(os.Args[2]); err != nil {
			return err
		}
		fmt.Printf("Successfully shimmed %s\n", os.Args[2])

	case "unshim":
		if len(os.Args) < 3 {
			return errors.New("usage: shmitm unshim <program>")
		}
		if err := unshim(os.Args[2]); err != nil {
			return err
		}

	case "monitor":
		if len(os.Args) < 3 {
			return errors.New("usage: shmitm monitor <program> [args...]")
		}
		return monitorBinary(os.Args[2])

	case "mitm":
		return runMitm()

	default:
		return fmt.Errorf("unknown command: %s", command)
	}
	return nil
}

func printUsage() {
	fmt.Println("Usage: shmitm <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  shim <program>     - Create a shim for the specified program")
	fmt.Println("  unshim <program>   - Remove shim and restore original program")
	fmt.Println("  monitor <program>  - Monitor file reads/writes by a program (Windows only)")
	fmt.Println("  mitm [addr]        - Start an HTTP/HTTPS intercepting proxy (default addr 0.0.0.0:8080)")
}
