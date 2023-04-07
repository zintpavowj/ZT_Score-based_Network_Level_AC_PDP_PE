// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_config.yml corresponds to a function of this package.
package init

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

func InitConfig(sysLogger *logrus.Logger) error {
	initDefaultValues(sysLogger)

	if err := initPe(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %s", err.Error())
	}

	return nil
}

// LoadX509KeyPair() unifies the loading of X509 key pairs for different components
func loadX509KeyPair(certfile, keyfile string) (tls.Certificate, error) {

	keyPair, err := tls.LoadX509KeyPair(certfile, keyfile)

	if err != nil {
		return tls.Certificate{}, err
	}

	return keyPair, nil
}

// function unifies the loading of CA certificates for different components
func loadCACertificate(certfile string, certPool *x509.CertPool) error {

	// Read the certificate file content
	caRoot, err := os.ReadFile(certfile)
	if err != nil {
		return err
	}

	// Return error if provided certificate is nil
	if certPool == nil {
		return errors.New("provided certPool is nil")
	}

	// Append a certificate to the pool
	if ok := certPool.AppendCertsFromPEM(caRoot); !ok {
		return errors.New("unable to append the certificate to the certificate pool")
	}

	return nil
}
