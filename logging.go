package main

import (
	"log"
	"os"
	"path/filepath"
)

var logFile *os.File

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
