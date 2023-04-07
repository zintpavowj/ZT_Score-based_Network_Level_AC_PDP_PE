package main

import (
	"crypto/x509"
	"flag"
	"log"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_PE/internal/app/config"
	confInit "github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_PE/internal/app/init"
	logger "github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_PE/internal/app/logger"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_PE/internal/app/router"
)

var (
	confFilePath string
	sysLogger    *logrus.Logger
)

func init() {
	var err error

	// Operating input parameters
	flag.StringVar(&confFilePath, "c", "./config/config.yml", "Path to user defined YML config file")
	flag.Parse()

	// Loading all config parameter from config file defined in "confFilePath"
	err = config.LoadConfig(confFilePath)
	if err != nil {
		log.Fatal(err)
	}

	// init system logger
	confInit.InitSysLoggerParams()

	// Create an instance of the system logger
	sysLogger = logrus.New()

	logger.SetLoggerDestination(sysLogger)
	logger.SetLoggerLevel(sysLogger)
	logger.SetLoggerFormatter(sysLogger)
	logger.SetupCloseHandler(sysLogger)

	sysLogger.Debugf("loading logger configuration from '%s' - OK", confFilePath)

	// Create Certificate Pools for the CA certificates used by the Policy Engine
	config.Config.CACertPoolToVerifyClientRequests = x509.NewCertPool()

	if err = confInit.InitConfig(sysLogger); err != nil {
		sysLogger.WithFields(logrus.Fields{
			"package":  "main",
			"function": "init",
		}).Fatal(err)
	}
}

func main() {
	// Create new PIP router
	pe, err := router.New(sysLogger)
	if err != nil {
		sysLogger.WithFields(logrus.Fields{
			"package":  "main",
			"function": "main",
			"comment":  "unable to create a new router",
		}).Fatal(err)
	}
	sysLogger.Debug("main: new router was successfully created")

	err = pe.ListenAndServeTLS()
	if err != nil {
		sysLogger.WithFields(logrus.Fields{
			"package":  "main",
			"function": "ListenAndServeTLS",
		}).Fatal(err)
	}
}
