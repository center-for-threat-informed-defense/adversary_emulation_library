package logger

import (
	"io"
	"log"
	"os"
	"runtime/debug"

	"github.com/fatih/color"
)

var (
	fileToLog string = "logs.txt"

	debugLogger   *log.Logger
	infoLogger    *log.Logger
	successLogger *log.Logger
	taskLogger    *log.Logger
	warningLogger *log.Logger
	errorLogger   *log.Logger
	fatalLogger   *log.Logger
	panicLogger   *log.Logger
	dataLogger    *log.Logger

	debugPrefix      string = "  [DEBUG] "
	infoPrefix       string = "   [INFO] "
	successPrefix    string = "[SUCCESS] "
	taskLoggerPrefix string = "   [TASK] "
	warningPrefix    string = "[WARNING] "
	errorPrefix      string = "  [ERROR] "
	fatalPrefx       string = "  [FATAL] "
	panicPrefix      string = "  [PANIC] "
	dataPrefix       string = "   [DATA] "
)

func SetLogs(fileToLog string) {
	logFile, err := os.OpenFile(fileToLog, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		panic(err)
	}
	stdoutAndLogFile := io.MultiWriter(os.Stdout, logFile)

	debugLogger = log.New(os.Stderr, debugPrefix, log.Ldate|log.Ltime)
	debugLogger.SetOutput(stdoutAndLogFile)

	infoLogger = log.New(os.Stdout, infoPrefix, log.Ldate|log.Ltime)
	infoLogger.SetOutput(stdoutAndLogFile)

	successLogger = log.New(os.Stdout, successPrefix, log.Ldate|log.Ltime)
	successLogger.SetOutput(stdoutAndLogFile)

	taskLogger = log.New(os.Stdout, taskLoggerPrefix, log.Ldate|log.Ltime)
	taskLogger.SetOutput(stdoutAndLogFile)

	warningLogger = log.New(os.Stdout, warningPrefix, log.Ldate|log.Ltime)
	warningLogger.SetOutput(stdoutAndLogFile)

	errorLogger = log.New(os.Stderr, errorPrefix, log.Ldate|log.Ltime)
	errorLogger.SetOutput(stdoutAndLogFile)

	fatalLogger = log.New(os.Stderr, fatalPrefx, log.Ldate|log.Ltime)
	fatalLogger.SetOutput(stdoutAndLogFile)

	panicLogger = log.New(os.Stderr, panicPrefix, log.Ldate|log.Ltime)
	panicLogger.SetOutput(stdoutAndLogFile)

	dataLogger = log.New(logFile, dataPrefix, log.Ldate|log.Ltime)

}

// init initializes each logger with its destination, prefix, and flags
func init() {
	SetLogs(fileToLog)
}

// Debug prints debug messages to standard err
func Debug(a ...interface{}) {
	color.Set(color.FgMagenta)
	defer color.Unset()
	debugLogger.Println(a...)
}

// Info prints informational messages to standard out
func Info(a ...interface{}) {
	color.Set(color.FgHiCyan)
	defer color.Unset()
	infoLogger.Println(a...)
}

// Success prints success messages to standard out
func Success(a ...interface{}) {
	color.Set(color.FgHiGreen)
	defer color.Unset()
	successLogger.Println(a...)
}

// Task is intended to print implant task output
func Task(a ...interface{}) {
	color.Set(color.FgHiMagenta)
	defer color.Unset()
	taskLogger.Println(a...)
}

// Warning prints warning messages, such as "are you sure" prompts
func Warning(a ...interface{}) {
	color.Set(color.FgYellow)
	defer color.Unset()
	warningLogger.Println(a...)
}

// Error prints error messages to standard err
func Error(a ...interface{}) {
	color.Set(color.FgRed)
	defer color.Unset()
	errorLogger.Println(a...)
}

// Fatal prints error messages to standard out and then exits the program
func Fatal(a ...interface{}) {
	color.Set(color.FgRed)
	defer color.Unset()
	fatalLogger.Println(a...)
	os.Exit(1)
}

// Panic prints out a stack trace then exits the program
func Panic(a ...interface{}) {
	color.Set(color.FgRed)
	defer color.Unset()
	panicLogger.Println(a...)
	debug.PrintStack()
	os.Exit(1)
}

// Data is intended to log data without printing
func Data(a ...interface{}) {
	dataLogger.Println(a...)
}
