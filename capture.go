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

// TODO support router
// TODO support dll

func applyReplacements(line string, patterns []*regexp.Regexp, replacements []string) string {
	result := line
	for i, re := range patterns {
		result = re.ReplaceAllString(result, replacements[i])
	}
	return result
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

	ext := filepath.Ext(exeName)
	realExeName := strings.TrimSuffix(exeName, ext) + "-real" + ext
	realExePath := filepath.Join(exeDir, realExeName)

	if _, err := os.Stat(realExePath); os.IsNotExist(err) {
		return fmt.Errorf("real executable not found: %s", realExePath)
	}

	cmd := exec.Command(realExePath, os.Args[1:]...)

	var err error
	if compiledConfig.PcapFile {
		err = runWithPcapCapture(cmd, captureDir, compiledConfig, realExePath)
	} else {
		if err := writeEnvironmentFiles(captureDir); err != nil {
			return err
		}
		err = runWithLineByLineCapture(cmd, captureDir, compiledConfig, realExePath)
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

func runWithPcapCapture(cmd *exec.Cmd, captureDir string, compiledConfig *CompiledConfig, realExePath string) error {
	pcapFile, err := os.Create(filepath.Join(captureDir, "capture.pcap"))
	if err != nil {
		return fmt.Errorf("failed to create pcap file: %w", err)
	}
	defer pcapFile.Close()

	pw, err := NewPcapWriter(pcapFile)
	if err != nil {
		return fmt.Errorf("failed to initialize pcap writer: %w", err)
	}

	var mu sync.Mutex
	writePacket := func(id StreamId, data []byte) {
		mu.Lock()
		defer mu.Unlock()
		if err := pw.WritePacket(os.Getpid(), id, data); err != nil {
			logMsg("Error writing pcap packet: %v", err)
		}
	}

	writePacket(StreamEnv, []byte(strings.Join(os.Environ(), "\n")))
	writePacket(StreamArgv, []byte(strings.Join(os.Args, "\n")))

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
		captureStreamToPcap(os.Stdin, stdinPipe, StreamStdin,
			compiledConfig.StdinReplacements, compiledConfig.StdinReplaceWith, writePacket)
	}()

	go func() {
		defer wg.Done()
		captureStreamToPcap(stdoutPipe, os.Stdout, StreamStdout,
			compiledConfig.StdoutReplacements, compiledConfig.StdoutReplaceWith, writePacket)
	}()

	go func() {
		defer wg.Done()
		captureStreamToPcap(stderrPipe, os.Stderr, StreamStderr,
			compiledConfig.StderrReplacements, compiledConfig.StderrReplaceWith, writePacket)
	}()

	cmd.Env = os.Environ()
	logMsg("Executing real program: %s with %d args (pcap mode)", realExePath, len(os.Args)-1)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start real executable: %w", err)
	}

	wg.Wait()
	return cmd.Wait()
}

func captureStreamToPcap(input io.Reader, output io.Writer, id StreamId, patterns []*regexp.Regexp, replacements []string, writePacket func(StreamId, []byte)) {
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		processed := applyReplacements(line, patterns, replacements)
		fmt.Fprintln(output, processed)
		writePacket(id, []byte(processed))
	}
	if err := scanner.Err(); err != nil {
		logMsg("Error reading stream: %v", err)
	}
}

func captureLineByLine(input io.Reader, output io.Writer, captureDir, streamName string, patterns []*regexp.Regexp, replacements []string) {
	scanner := bufio.NewScanner(input)
	lineCounter := 0

	for scanner.Scan() {
		originalLine := scanner.Text()
		lineCounter++

		processedLine := applyReplacements(originalLine, patterns, replacements)

		fmt.Fprintln(output, processedLine)

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
