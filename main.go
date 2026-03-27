package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TODO also shim a dll. somehow

/*
"Accomplishing","Actioning","Actualizing","Baking","Booping","Brewing",
"Calculating","Cerebrating","Channelling","Churning","Clauding","Coalescing",
"Cogitating","Computing","Combobulating","Concocting","Considering","Contemplating",
"Cooking","Crafting","Creating","Crunching","Deciphering","Deliberating","Determining",
"Discombobulating","Doing","Effecting","Elucidating","Enchanting","Envisioning",
"Finagling","Flibbertigibbeting","Forging","Forming","Frolicking","Generating",
"Germinating","Hatching","Herding","Honking","Ideating","Imagining","Incubating",
"Inferring","Manifesting","Marinating","Meandering","Moseying","Mulling","Mustering",
"Musing","Noodling","Percolating","Perusing","Philosophising","Pontificating",
"Pondering","Processing","Puttering","Puzzling","Reticulating","Ruminating",
"Scheming","Schlepping","Shimmying","Simmering","Smooshing","Spelunking","Spinning",
"Stewing","Sussing","Synthesizing","Thinking","Tinkering","Transmuting",
"Unfurling","Unravelling","Vibing","Wandering","Whirring","Wibbling",
"Working","Wrangling"
*/

var logFile *os.File

// RegexReplacement defines a regex pattern replacement rule
type RegexReplacement struct {
	Stream  string `json:"stream"`  // "stdout", "stderr", or "all"
	Pattern string `json:"pattern"` // regex pattern to match
	Replace string `json:"replace"` // replacement string
}

// Config holds the application configuration
type Config struct {
	// OneFilePerLine determines the output capture mode:
	// true: each line of output gets its own timestamped file
	// false: one file per stream (stdout, stderr, stdin)
	OneFilePerLine bool `json:"one_file_per_line"`

	// RegexReplacements defines patterns to replace in stream output
	RegexReplacements []RegexReplacement `json:"regex_replacements"`
}

// CompiledConfig holds the parsed configuration with compiled regexes
type CompiledConfig struct {
	OneFilePerLine     bool
	StdoutReplacements []*regexp.Regexp
	StdoutReplaceWith  []string
	StderrReplacements []*regexp.Regexp
	StderrReplaceWith  []string
}

// DefaultConfig returns the default configuration
func DefaultConfig() Config {
	return Config{
		OneFilePerLine: true,
	}
}

// LoadConfig loads configuration from config.json if it exists,
// otherwise returns default configuration
func LoadConfig() Config {
	exePath, err := os.Executable()
	if err != nil {
		return DefaultConfig()
	}
	exeDir := filepath.Dir(exePath)
	configPath := filepath.Join(exeDir, "config.json")

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return DefaultConfig()
	}

	// Read and parse config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		logMsg("Error reading config file: %v, using defaults", err)
		return DefaultConfig()
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		logMsg("Error parsing config file: %v, using defaults", err)
		return DefaultConfig()
	}

	logMsg("Loaded config: OneFilePerLine=%v, RegexReplacements=%d", config.OneFilePerLine, len(config.RegexReplacements))
	return config
}

// CompileConfig compiles regex patterns in the config
func CompileConfig(config Config) (*CompiledConfig, error) {
	compiled := &CompiledConfig{
		OneFilePerLine: config.OneFilePerLine,
	}

	for _, rule := range config.RegexReplacements {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern '%s': %w", rule.Pattern, err)
		}

		switch rule.Stream {
		case "stdout", "all":
			compiled.StdoutReplacements = append(compiled.StdoutReplacements, re)
			compiled.StdoutReplaceWith = append(compiled.StdoutReplaceWith, rule.Replace)
		}

		switch rule.Stream {
		case "stderr", "all":
			compiled.StderrReplacements = append(compiled.StderrReplacements, re)
			compiled.StderrReplaceWith = append(compiled.StderrReplaceWith, rule.Replace)
		}
	}

	return compiled, nil
}

func initLog() {
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	logPath := filepath.Join(exeDir, "shimmer.log")

	var err error
	logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// If we can't open the log file, just silently fail
		return
	}
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime)
}

func logMsg(format string, args ...any) {
	if logFile != nil {
		log.Printf(format, args...)
	}
}

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
		filename := filepath.Join(captureDir, fmt.Sprintf("%s_%04d_%s.txt", streamName, lineCounter, timestamp))

		content := fmt.Sprintf("# Captured at: %s\n# Stream: %s\n# Line: %d\n%s\n",
			time.Now().Format(time.RFC3339Nano),
			streamName,
			lineCounter,
			processedLine)

		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			logMsg("Error writing %s line %d to file: %v", streamName, lineCounter, err)
		}
	}

	if err := scanner.Err(); err != nil {
		logMsg("Error reading from %s: %v", streamName, err)
	}
}

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
		if len(os.Args) < 2 {
			fmt.Println("Usage: shimmer <command> [args]")
			fmt.Println("Commands:")
			fmt.Println("  setup <program>    - Create a shim for the specified program")
			fmt.Println("  unshim <program>   - Remove shim and restore original program")
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
			return
		case "unshim", "remove":
			if len(os.Args) < 3 {
				fmt.Println("Usage: shimmer unshim <program>")
				os.Exit(1)
			}
			if err := unshim(os.Args[2]); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			return
		default:
			fmt.Printf("Unknown command: %s\n", command)
			os.Exit(1)
		}
	}

	// Load configuration
	config := LoadConfig()
	compiledConfig, err := CompileConfig(config)
	if err != nil {
		logMsg("Error compiling config: %v", err)
		fmt.Fprintf(os.Stderr, "Error: invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Normal shim behavior below
	// Create capture folder with timestamp
	exeDir := filepath.Dir(exePath)
	timestamp := time.Now().Format("20060102_150405_000")
	captureDir := filepath.Join(exeDir, fmt.Sprintf("capture_%s_%s", nameWithoutExt, timestamp))

	logMsg("Intercepting call to %s, capture dir: %s", nameWithoutExt, captureDir)

	if err := os.MkdirAll(captureDir, 0755); err != nil {
		logMsg("Error creating capture directory: %v", err)
		os.Exit(1)
	}

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

	// Determine the real executable path (reuse exeName from above)
	ext := filepath.Ext(exeName)
	realExeName := strings.TrimSuffix(exeName, ext) + "-real" + ext
	realExePath := filepath.Join(exeDir, realExeName)

	// Check if the real executable exists
	if _, err := os.Stat(realExePath); os.IsNotExist(err) {
		logMsg("Real executable not found: %s", realExePath)
		os.Exit(1)
	}

	// Prepare the command to execute the real executable
	// Pass all arguments except the first one (which is this program's path)
	cmd := exec.Command(realExePath, os.Args[1:]...)

	// Setup stdin capture (always one file for stdin)
	stdinFile := filepath.Join(captureDir, "stdin.txt")
	stdinCapture, err := os.Create(stdinFile)
	if err != nil {
		logMsg("Error creating stdin file: %v", err)
		os.Exit(1)
	}
	defer stdinCapture.Close()
	cmd.Stdin = io.TeeReader(os.Stdin, stdinCapture)

	// Choose capture mode based on config
	if compiledConfig.OneFilePerLine {
		// One file per line mode
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
		err = cmd.Wait()
	} else {
		// One file per stream mode with regex replacement support
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
			err = cmd.Wait()
		} else {
			// No regex replacements, use original MultiWriter approach
			cmd.Stdout = io.MultiWriter(os.Stdout, stdoutCapture)
			cmd.Stderr = io.MultiWriter(os.Stderr, stderrCapture)
			cmd.Env = os.Environ()

			logMsg("Executing real program: %s with %d args (one-file-per-stream mode)", realExePath, len(os.Args)-1)
			err = cmd.Run()
		}
	}

	if err != nil {
		// If the command failed, exit with the same error code
		if exitErr, ok := err.(*exec.ExitError); ok {
			logMsg("Program exited with code %d", exitErr.ExitCode())
			os.Exit(exitErr.ExitCode())
		}
		logMsg("Error executing real executable: %v", err)
		os.Exit(1)
	}

	logMsg("Program completed successfully")
}
