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

func executeShimmedProgram(exePath, exeName, nameWithoutExt string, compiledConfig *CompiledConfig) error {
	exeDir := filepath.Dir(exePath)
	timestamp := time.Now().Format("20060102_150405_000")

	baseDir := exeDir
	if compiledConfig.CapturePath != "" && compiledConfig.CapturePath != "." {
		if !filepath.IsAbs(compiledConfig.CapturePath) {
			baseDir = filepath.Join(exeDir, compiledConfig.CapturePath)
		} else {
			baseDir = compiledConfig.CapturePath
		}
	}

	captureDir := filepath.Join(baseDir, fmt.Sprintf("capture_%s_%s", nameWithoutExt, timestamp))

	if err := os.MkdirAll(captureDir, 0755); err != nil {
		return fmt.Errorf("failed to create capture directory: %w", err)
	}

	initLog(captureDir)
	if logFile != nil {
		defer logFile.Close()
	}

	logMsg("Intercepting call to %s, capture dir: %s", nameWithoutExt, captureDir)

	if err := writeEnvironmentFiles(captureDir); err != nil {
		return err
	}

	ext := filepath.Ext(exeName)
	realExeName := strings.TrimSuffix(exeName, ext) + "-real" + ext
	realExePath := filepath.Join(exeDir, realExeName)

	if _, err := os.Stat(realExePath); os.IsNotExist(err) {
		return fmt.Errorf("real executable not found: %s", realExePath)
	}

	cmd := exec.Command(realExePath, os.Args[1:]...)

	var err error
	if compiledConfig.OneFilePerLine {
		err = runWithLineByLineCapture(cmd, captureDir, compiledConfig, realExePath)
	} else {
		err = runWithStreamCapture(cmd, captureDir, compiledConfig, realExePath)
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logMsg("Program exited with code %d", exitErr.ExitCode())
		}
		return err
	}

	logMsg("Program completed successfully")
	return nil
}

func writeEnvironmentFiles(captureDir string) error {
	envFile := filepath.Join(captureDir, "environment.txt")
	if err := os.WriteFile(envFile, []byte(strings.Join(os.Environ(), "\n")), 0644); err != nil {
		return fmt.Errorf("failed to write environment: %w", err)
	}

	argsFile := filepath.Join(captureDir, "arguments.txt")
	if err := os.WriteFile(argsFile, []byte(strings.Join(os.Args, "\n")), 0644); err != nil {
		return fmt.Errorf("failed to write arguments: %w", err)
	}
	return nil
}

func runWithLineByLineCapture(cmd *exec.Cmd, captureDir string, compiledConfig *CompiledConfig, realExePath string) error {
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		defer stdinPipe.Close()
		captureLineByLine(os.Stdin, stdinPipe, captureDir, "stdin",
			compiledConfig.StdinReplacements, compiledConfig.StdinReplaceWith)
	}()

	go func() {
		defer wg.Done()
		captureLineByLine(stdoutPipe, os.Stdout, captureDir, "stdout",
			compiledConfig.StdoutReplacements, compiledConfig.StdoutReplaceWith)
	}()

	go func() {
		defer wg.Done()
		captureLineByLine(stderrPipe, os.Stderr, captureDir, "stderr",
			compiledConfig.StderrReplacements, compiledConfig.StderrReplaceWith)
	}()

	cmd.Env = os.Environ()
	logMsg("Executing real program: %s with %d args (one-file-per-line mode)", realExePath, len(os.Args)-1)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start real executable: %w", err)
	}

	wg.Wait()
	return cmd.Wait()
}

func runWithStreamCapture(cmd *exec.Cmd, captureDir string, compiledConfig *CompiledConfig, realExePath string) error {
	stdinFile := filepath.Join(captureDir, "stdin.txt")
	stdinCapture, err := os.Create(stdinFile)
	if err != nil {
		return fmt.Errorf("failed to create stdin file: %w", err)
	}
	defer stdinCapture.Close()
	cmd.Stdin = io.TeeReader(os.Stdin, stdinCapture)

	stdoutCapture, err := os.Create(filepath.Join(captureDir, "stdout.txt"))
	if err != nil {
		return fmt.Errorf("failed to create stdout file: %w", err)
	}
	defer stdoutCapture.Close()

	stderrCapture, err := os.Create(filepath.Join(captureDir, "stderr.txt"))
	if err != nil {
		return fmt.Errorf("failed to create stderr file: %w", err)
	}
	defer stderrCapture.Close()

	if len(compiledConfig.StdoutReplacements) > 0 || len(compiledConfig.StderrReplacements) > 0 {
		return runWithRegexReplacements(cmd, stdoutCapture, stderrCapture, compiledConfig, realExePath)
	}

	cmd.Stdout = io.MultiWriter(os.Stdout, stdoutCapture)
	cmd.Stderr = io.MultiWriter(os.Stderr, stderrCapture)
	cmd.Env = os.Environ()

	logMsg("Executing real program: %s with %d args (one-file-per-stream mode)", realExePath, len(os.Args)-1)
	return cmd.Run()
}

func runWithRegexReplacements(cmd *exec.Cmd, stdoutCapture, stderrCapture *os.File, compiledConfig *CompiledConfig, realExePath string) error {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

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
		return fmt.Errorf("failed to start real executable: %w", err)
	}

	wg.Wait()
	return cmd.Wait()
}
