// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_config.yml corresponds to a function of this package.
package init

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_PE/internal/app/config"
)

// The function initializes the 'pe' section of the config file and
// loads the Policy Engine certificate(s).
func initPe(sysLogger *logrus.Logger) error {
	var err error
	var fields string = ""

	if config.Config.Pe.ListenAddr == "" {
		fields += "listen_addr,"
	}

	if config.Config.Pe.SSLCert == "" {
		fields += "ssl_cert,"
	}

	if config.Config.Pe.SSLCertKey == "" {
		fields += "ssl_cert_key,"
	}

	if config.Config.Pe.CACertsToVerifyClientRequests == nil {
		fields += "ca_certs_to_verify_client_certs,"
	}

	if fields != "" {
		return fmt.Errorf("initPe(): in the section 'pe' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Read CA certs used to verify certs to be accepted
	for _, acceptedClientCert := range config.Config.Pe.CACertsToVerifyClientRequests {

		err = loadCACertificate(acceptedClientCert, config.Config.CACertPoolToVerifyClientRequests)
		if err != nil {
			sysLogger.WithFields(logrus.Fields{
				"package":  "init",
				"function": "initPe",
				"comment":  "unable to load a CA certificate to eccept incoming requests",
				"cafile":   acceptedClientCert,
			}).Error(err)
			return err
		}

		sysLogger.WithFields(logrus.Fields{
			"package":  "init",
			"function": "initPe",
			"cafile":   acceptedClientCert,
		}).Debug("a CA certificate has been loaded successfully")

	}

	// Load Policy Engine certificate
	config.Config.PeCert, err = loadX509KeyPair(config.Config.Pe.SSLCert, config.Config.Pe.SSLCertKey)
	if err != nil {
		sysLogger.WithFields(logrus.Fields{
			"package":  "init",
			"function": "initPe",
			"comment":  "unable to load a x509 certificate",
			"certfile": config.Config.Pe.SSLCert,
			"keyfile":  config.Config.Pe.SSLCertKey,
		}).Error(err)
		return err
	}

	sysLogger.WithFields(logrus.Fields{
		"package":  "init",
		"function": "initPe",
		"certfile": config.Config.Pe.SSLCert,
		"keyfile":  config.Config.Pe.SSLCertKey,
	}).Debug("a x509 certificate has been loaded successfully")

	return nil
}
