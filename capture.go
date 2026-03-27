package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// applyReplacements applies regex replacements to a line
func applyReplacements(line string, patterns []*regexp.Regexp, replacements []string) string {
	result := line
	for i, re := range patterns {
		result = re.ReplaceAllString(result, replacements[i])
	}
	return result
}

// captureLineByLine reads from input line by line, writes each line to both
// output (for passthrough) and to individual timestamped files in captureDir
func captureLineByLine(input io.Reader, output io.Writer, captureDir, streamName string, patterns []*regexp.Regexp, replacements []string) {
	scanner := bufio.NewScanner(input)
	lineCounter := 0

	for scanner.Scan() {
		originalLine := scanner.Text()
		lineCounter++

		// Apply regex replacements
		processedLine := applyReplacements(originalLine, patterns, replacements)

		// Write processed line to output for passthrough
		fmt.Fprintln(output, processedLine)

		// Create individual file for this line
		timestamp := time.Now().Format("20060102_150405.000000")
		filename := filepath.Join(captureDir, fmt.Sprintf("%s_%s_%04d.txt", timestamp, streamName, lineCounter))

		if err := os.WriteFile(filename, []byte(processedLine), 0644); err != nil {
			logMsg("Error writing %s line %d to file: %v", streamName, lineCounter, err)
		}
	}

	if err := scanner.Err(); err != nil {
		logMsg("Error reading from %s: %v", streamName, err)
	}
}

func executeShimmedProgram(exePath, exeName, nameWithoutExt string, compiledConfig *CompiledConfig) {
	// Create capture folder with timestamp
	exeDir := filepath.Dir(exePath)
	timestamp := time.Now().Format("20060102_150405_000")

	// Determine base directory for captures
	baseDir := exeDir
	if compiledConfig.CapturePath != "" && compiledConfig.CapturePath != "." {
		// If path is relative, make it relative to executable directory
		if !filepath.IsAbs(compiledConfig.CapturePath) {
			baseDir = filepath.Join(exeDir, compiledConfig.CapturePath)
		} else {
			baseDir = compiledConfig.CapturePath
		}
	}

	captureDir := filepath.Join(baseDir, fmt.Sprintf("capture_%s_%s", nameWithoutExt, timestamp))

	if err := os.MkdirAll(captureDir, 0755); err != nil {
		// Can't log yet since capture dir creation failed
		os.Exit(1)
	}

	// Initialize logging in the capture directory
	initLog(captureDir)
	if logFile != nil {
		defer logFile.Close()
	}

	logMsg("Intercepting call to %s, capture dir: %s", nameWithoutExt, captureDir)

	// Write environment and arguments
	writeEnvironmentFiles(captureDir)

	// Determine the real executable path
	ext := filepath.Ext(exeName)
	realExeName := strings.TrimSuffix(exeName, ext) + "-real" + ext
	realExePath := filepath.Join(exeDir, realExeName)

	// Check if the real executable exists
	if _, err := os.Stat(realExePath); os.IsNotExist(err) {
		logMsg("Real executable not found: %s", realExePath)
		os.Exit(1)
	}

	// Prepare the command
	cmd := exec.Command(realExePath, os.Args[1:]...)

	// Execute based on capture mode
	var err error
	if compiledConfig.OneFilePerLine {
		err = runWithLineByLineCapture(cmd, captureDir, compiledConfig, realExePath)
	} else {
		err = runWithStreamCapture(cmd, captureDir, compiledConfig, realExePath)
	}

	// Handle exit codes
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logMsg("Program exited with code %d", exitErr.ExitCode())
			os.Exit(exitErr.ExitCode())
		}
		logMsg("Error executing real executable: %v", err)
		os.Exit(1)
	}

	logMsg("Program completed successfully")
}

func writeEnvironmentFiles(captureDir string) {
	// Write environment variables to file
	envFile := filepath.Join(captureDir, "environment.txt")
	envData := strings.Join(os.Environ(), "\n")
	if err := os.WriteFile(envFile, []byte(envData), 0644); err != nil {
		logMsg("Error writing environment: %v", err)
		os.Exit(1)
	}

	// Write arguments to file
	argsFile := filepath.Join(captureDir, "arguments.txt")
	argsData := strings.Join(os.Args, "\n")
	if err := os.WriteFile(argsFile, []byte(argsData), 0644); err != nil {
		logMsg("Error writing arguments: %v", err)
		os.Exit(1)
	}
}

func runWithLineByLineCapture(cmd *exec.Cmd, captureDir string, compiledConfig *CompiledConfig, realExePath string) error {
	// Setup stdin pipe
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		logMsg("Error creating stdin pipe: %v", err)
		os.Exit(1)
	}

	// Setup pipes for stdout and stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		logMsg("Error creating stdout pipe: %v", err)
		os.Exit(1)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		logMsg("Error creating stderr pipe: %v", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	wg.Add(3)

	// Handle stdin line by line
	go func() {
		defer wg.Done()
		defer stdinPipe.Close()
		captureLineByLine(os.Stdin, stdinPipe, captureDir, "stdin",
			compiledConfig.StdinReplacements, compiledConfig.StdinReplaceWith)
	}()

	// Handle stdout line by line
	go func() {
		defer wg.Done()
		captureLineByLine(stdoutPipe, os.Stdout, captureDir, "stdout",
			compiledConfig.StdoutReplacements, compiledConfig.StdoutReplaceWith)
	}()

	// Handle stderr line by line
	go func() {
		defer wg.Done()
		captureLineByLine(stderrPipe, os.Stderr, captureDir, "stderr",
			compiledConfig.StderrReplacements, compiledConfig.StderrReplaceWith)
	}()

	cmd.Env = os.Environ()
	logMsg("Executing real program: %s with %d args (one-file-per-line mode)", realExePath, len(os.Args)-1)

	if err := cmd.Start(); err != nil {
		logMsg("Error starting real executable: %v", err)
		os.Exit(1)
	}

	wg.Wait()
	return cmd.Wait()
}

func runWithStreamCapture(cmd *exec.Cmd, captureDir string, compiledConfig *CompiledConfig, realExePath string) error {
	// Setup stdin capture
	stdinFile := filepath.Join(captureDir, "stdin.txt")
	stdinCapture, err := os.Create(stdinFile)
	if err != nil {
		logMsg("Error creating stdin file: %v", err)
		os.Exit(1)
	}
	defer stdinCapture.Close()
	cmd.Stdin = io.TeeReader(os.Stdin, stdinCapture)

	// Create output files
	stdoutFile := filepath.Join(captureDir, "stdout.txt")
	stderrFile := filepath.Join(captureDir, "stderr.txt")

	stdoutCapture, err := os.Create(stdoutFile)
	if err != nil {
		logMsg("Error creating stdout file: %v", err)
		os.Exit(1)
	}
	defer stdoutCapture.Close()

	stderrCapture, err := os.Create(stderrFile)
	if err != nil {
		logMsg("Error creating stderr file: %v", err)
		os.Exit(1)
	}
	defer stderrCapture.Close()

	// If we have regex replacements, use pipes to apply them
	if len(compiledConfig.StdoutReplacements) > 0 || len(compiledConfig.StderrReplacements) > 0 {
		return runWithRegexReplacements(cmd, stdoutCapture, stderrCapture, compiledConfig, realExePath)
	}

	// No regex replacements, use original MultiWriter approach
	cmd.Stdout = io.MultiWriter(os.Stdout, stdoutCapture)
	cmd.Stderr = io.MultiWriter(os.Stderr, stderrCapture)
	cmd.Env = os.Environ()

	logMsg("Executing real program: %s with %d args (one-file-per-stream mode)", realExePath, len(os.Args)-1)
	return cmd.Run()
}

func runWithRegexReplacements(cmd *exec.Cmd, stdoutCapture, stderrCapture *os.File, compiledConfig *CompiledConfig, realExePath string) error {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		logMsg("Error creating stdout pipe: %v", err)
		os.Exit(1)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		logMsg("Error creating stderr pipe: %v", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Handle stdout with replacements
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()
			processedLine := applyReplacements(line, compiledConfig.StdoutReplacements, compiledConfig.StdoutReplaceWith)
			fmt.Fprintln(os.Stdout, processedLine)
			fmt.Fprintln(stdoutCapture, processedLine)
		}
	}()

	// Handle stderr with replacements
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			processedLine := applyReplacements(line, compiledConfig.StderrReplacements, compiledConfig.StderrReplaceWith)
			fmt.Fprintln(os.Stderr, processedLine)
			fmt.Fprintln(stderrCapture, processedLine)
		}
	}()

	cmd.Env = os.Environ()
	logMsg("Executing real program: %s with %d args (one-file-per-stream mode with regex)", realExePath, len(os.Args)-1)

	if err := cmd.Start(); err != nil {
		logMsg("Error starting real executable: %v", err)
		os.Exit(1)
	}

	wg.Wait()
	return cmd.Wait()
}
