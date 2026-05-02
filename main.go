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
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exeName := filepath.Base(exePath)
	nameWithoutExt := strings.TrimSuffix(exeName, filepath.Ext(exeName))

	if nameWithoutExt == "shimmer" {
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
	case "setup":
		if len(os.Args) < 3 {
			return errors.New("usage: shimmer setup <program>")
		}
		if err := setupShim(os.Args[2]); err != nil {
			return err
		}
		fmt.Printf("Successfully shimmed %s\n", os.Args[2])

	case "unshim", "remove":
		if len(os.Args) < 3 {
			return errors.New("usage: shimmer unshim <program>")
		}
		if err := unshim(os.Args[2]); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown command: %s", command)
	}
	return nil
}

func printUsage() {
	fmt.Println("Usage: shimmer <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  setup <program>    - Create a shim for the specified program")
	fmt.Println("  unshim <program>   - Remove shim and restore original program")
}
