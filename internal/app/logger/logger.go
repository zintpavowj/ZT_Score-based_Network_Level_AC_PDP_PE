package logger

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_PE/internal/app/config"
)

var logFile *os.File

func SetLoggerDestination(logger *logrus.Logger) error {
	var err error

	//Get the Destination from the config
	dest := config.Config.SysLogger.LogDestination

	// Set the os.Stdout or a file for writing the log messages
	if len(dest) == 0 || strings.ToLower(dest) == "stdout" {

		// If the destination is not configured or set to stdout explicitly
		logger.SetOutput(os.Stdout)

	} else {

		// Open a file for the logger output
		logFile, err = os.OpenFile(dest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("logger: New(): unable to open the file '%s' for writing: %s", dest, err.Error())
		}

		// Redirect the logger output to the file
		logger.SetOutput(logFile)
	}

	return nil
}

func SetLoggerLevel(logger *logrus.Logger) error {
	var err error
	var level logrus.Level
	levelStr := config.Config.SysLogger.LogLevel

	// If the logging level is not configured,the "info" logging level is used,
	// since an http.Server and httputil.ReverseProxy use it when send
	// messages to a given Writer.
	if levelStr == "" {
		level, err = logrus.ParseLevel("info")
		if err != nil {
			return fmt.Errorf("logger: New(): unable to set the logging level 'info': %s", err.Error())
		}
		logger.SetLevel(level)
		return nil
	}

	// Set the logging level
	level, err = logrus.ParseLevel(levelStr)
	if err != nil {
		return fmt.Errorf("logger: New(): unable to set the logging level '%s': %s", levelStr, err.Error())
	}
	logger.SetLevel(level)

	return nil
}

// The function sets the logger formatter (mainly logrus.TextFormatter{} or logrus.JSONFormatter{})
func SetLoggerFormatter(logger *logrus.Logger) error {

	// Set the logger formatter
	switch strings.ToLower(config.Config.SysLogger.LogFormatter) {

	// If not configured, the JSON formatter is used as the default one
	case "":
		fallthrough
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{})

	case "text":
		logger.SetFormatter(&logrus.TextFormatter{})

	default:
		return fmt.Errorf("logger: New(): unknown logger formatter '%s'", config.Config.SysLogger.LogFormatter)
	}
	return nil
}

func SetupCloseHandler(logger *logrus.Logger) {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		logger.Debug("- 'Ctrl + C' was pressed in the Terminal. Terminating...")

		// Close a logFile before exit
		if logFile != nil {
			logFile.Close()
		}

		os.Exit(0)
	}()
}
