package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// Initialize logging
	initLog()
	if logFile != nil {
		defer logFile.Close()
	}

	// Check if we're running as "shimmer" for meta commands
	exePath, err := os.Executable()
	if err != nil {
		logMsg("Error getting executable path: %v", err)
		os.Exit(1)
	}
	exeName := filepath.Base(exePath)
	nameWithoutExt := strings.TrimSuffix(exeName, filepath.Ext(exeName))

	// Handle meta commands when running as "shimmer"
	if nameWithoutExt == "shimmer" {
		handleMetaCommands()
		return
	}

	// Load and compile configuration
	config := LoadConfig()
	compiledConfig, err := CompileConfig(config)
	if err != nil {
		logMsg("Error compiling config: %v", err)
		fmt.Fprintf(os.Stderr, "Error: invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Execute the shimmed program
	executeShimmedProgram(exePath, exeName, nameWithoutExt, compiledConfig)
}

func handleMetaCommands() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "setup":
		if len(os.Args) < 3 {
			fmt.Println("Usage: shimmer setup <program>")
			os.Exit(1)
		}
		if err := setupShim(os.Args[2]); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully shimmed %s\n", os.Args[2])

	case "unshim", "remove":
		if len(os.Args) < 3 {
			fmt.Println("Usage: shimmer unshim <program>")
			os.Exit(1)
		}
		if err := unshim(os.Args[2]); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: shimmer <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  setup <program>    - Create a shim for the specified program")
	fmt.Println("  unshim <program>   - Remove shim and restore original program")
}
