package init

import "github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_PE/internal/app/config"

// InitSysLoggerParams() sets default values for the system logger parameters
// The function should be called before the system logger creation!
func InitSysLoggerParams() {
	// Set a default value of a logging level parameter
	if config.Config.SysLogger.LogLevel == "" {
		config.Config.SysLogger.LogLevel = "info"
	}

	// Set a default value of a log messages destination parameter
	if config.Config.SysLogger.LogDestination == "" {
		config.Config.SysLogger.LogDestination = "stdout"
	}

	// Set a default value of a log messages formatter parameter
	if config.Config.SysLogger.LogFormatter == "" {
		config.Config.SysLogger.LogFormatter = "json"
	}
}
