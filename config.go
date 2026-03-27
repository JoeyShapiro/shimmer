package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// RegexReplacement defines a regex pattern replacement rule
type RegexReplacement struct {
	Stream  string `json:"stream"`  // "stdin", "stdout", "stderr", or "all"
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
	StdinReplacements  []*regexp.Regexp
	StdinReplaceWith   []string
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
		case "stdin", "all":
			compiled.StdinReplacements = append(compiled.StdinReplacements, re)
			compiled.StdinReplaceWith = append(compiled.StdinReplaceWith, rule.Replace)
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
