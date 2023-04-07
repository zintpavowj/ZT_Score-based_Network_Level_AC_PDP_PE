package apicaller

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_PE/internal/app/config"
)

type APICaller struct {
	Client    *http.Client
	sysLogger *logrus.Logger
}

func New(logger *logrus.Logger) (*APICaller, error) {

	caller := new(APICaller)
	caller.sysLogger = logger

	cert, err := tls.LoadX509KeyPair(config.Config.Pe.SSLCert, config.Config.Pe.SSLCertKey)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"package":  "apicaller",
			"function": "New",
			"comment":  "unable to load a x509 certificate",
			"certfile": config.Config.Pe.SSLCert,
			"keyfile":  config.Config.Pe.SSLCertKey,
		}).Fatal(err)
	}

	// Create a CA certificate pool
	caCert, err := os.ReadFile(config.Config.Pe.CACertsToVerifyClientRequests[0])
	if err != nil {
		logger.WithFields(logrus.Fields{
			"package":  "apicaller",
			"function": "New",
			"comment":  "unable to load a ca file",
			"cafile":   config.Config.Pe.CACertsToVerifyClientRequests[0],
		}).Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a HTTPS client and supply the created CA pool and certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	caller.Client = client

	return caller, nil
}
