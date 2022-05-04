package logger

import (
	"io/ioutil"
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
	warningLogger *log.Logger
	errorLogger   *log.Logger
	fatalLogger   *log.Logger
	panicLogger   *log.Logger

	debugPrefix   string = "  [DEBUG] "
	infoPrefix    string = "   [INFO] "
	successPrefix string = "[SUCCESS] "
	warningPrefix string = "[WARNING] "
	errorPrefix   string = "  [ERROR] "
	fatalPrefx    string = "  [FATAL] "
	panicPrefix   string = "  [PANIC] "
)

// init initializes each logger with its destination, prefix, and flags
func init() {
	debugLogger = log.New(os.Stderr, debugPrefix, log.Ldate|log.Ltime)
	infoLogger = log.New(os.Stdout, infoPrefix, log.Ldate|log.Ltime)
	successLogger = log.New(os.Stdout, successPrefix, log.Ldate|log.Ltime)
	warningLogger = log.New(os.Stdout, warningPrefix, log.Ldate|log.Ltime)
	errorLogger = log.New(os.Stderr, errorPrefix, log.Ldate|log.Ltime)
	fatalLogger = log.New(os.Stderr, fatalPrefx, log.Ldate|log.Ltime)
	panicLogger = log.New(os.Stderr, panicPrefix, log.Ldate|log.Ltime)
}

// If app not started with debugging enabled, don't output any logs
func DisableLogging() {
	loggers := []*log.Logger{
		debugLogger,
		infoLogger,
		successLogger,
		warningLogger,
		errorLogger,
		fatalLogger,
		panicLogger,
	}
	for _, logger := range loggers {
		logger.SetOutput(ioutil.Discard)
	}
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
