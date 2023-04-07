// Package router contains the main routine of the PIP service.
package router

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	apicaller "github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_PE/internal/app/apiCaller"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_PE/internal/app/config"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_PE/internal/app/scenario"
)

type Router struct {
	tlsConfig *tls.Config
	frontend  *http.Server
	sysLogger *logrus.Logger
	caller    *apicaller.APICaller
}

type PapPolicyT struct { 
	Algorithm string `json:"algorithm"`
	Threshold string `json:"threshold"`
}

func New(logger *logrus.Logger) (*Router, error) {
	var err error

	r := new(Router)

	// Set sysLogger to the one created in the init function
	r.sysLogger = logger

	// Configure the TLS configuration of the router
	r.tlsConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    config.Config.CACertPoolToVerifyClientRequests,
		Certificates: []tls.Certificate{config.Config.PeCert},
	}

	// Frontend Handlers
	mux := http.NewServeMux()
	mux.Handle("/", r)

	w := logger.Writer()

	// Setting Up the Frontend Server
	r.frontend = &http.Server{
		Addr:         config.Config.Pe.ListenAddr,
		TLSConfig:    r.tlsConfig,
		ReadTimeout:  time.Hour * 1,
		WriteTimeout: time.Hour * 1,
		Handler:      mux,
		ErrorLog:     log.New(w, "", 0),
	}

	r.caller, err = apicaller.New(logger)
	if err != nil {
		logger.Errorf("main: main(): unable to create an caller: %s", err.Error())
	}
	logger.Debug("a new apicaller has been created")

	return r, nil
}

// ServeHTTP gets called if a request receives the PEP. The function implements
// the PEP's main routine: It performs basic authentication, authorization with
// help of the PEP, transformation from SFCs into SFPs with help of the SFP
// Logic, and then forwards the package along the SFP.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var err error
	var resp *http.Response
	var sc scenario.Scenario

	err = json.NewDecoder(req.Body).Decode(&sc)
	if err != nil {
		r.sysLogger.WithFields(logrus.Fields{
			"package":    "router",
			"function":   "ServeHTTP",
			"httpStatus": http.StatusBadRequest,
			"comment":    "unable to decode a scenario from an input request",
		}).Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.sysLogger.Debugf("scenario %d starts:", sc.Id)

	policies, err := r.GetPolicies(sc.Service, sc.Action, sc.User.Name)
	if err != nil {
		r.sysLogger.WithFields(logrus.Fields{
			"package":    "router",
			"function":   "ServeHTTP",
			"httpStatus": http.StatusBadRequest,
			"comment":    "unable to get policies from the policy administration point",
		}).Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.sysLogger.Debugf(
		"policy administratiuon point responded: 'algorithm=%s, threshold=%s'",
		policies.Algorithm,
		policies.Threshold,
	)

	resp, err = r.CallTrustCalculationAlgorithm(sc, policies)
	if err != nil {
		return
	}

	var output []string
	err = json.NewDecoder(resp.Body).Decode(&output)
	if err != nil {
		r.sysLogger.WithFields(logrus.Fields{
			"package":   "router",
			"function":  "ServeHTTP",
			"algorithm": policies.Algorithm,
			"threshold": policies.Threshold,
			"comment":   "unable to decode a trust algorithm response",
		}).Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch resp.StatusCode {

	case http.StatusUnauthorized:
		r.sysLogger.WithFields(logrus.Fields{
			"package":                "router",
			"function":               "ServeHTTP",
			"algorithm":              policies.Algorithm,
			"threshold":              policies.Threshold,
			"authorization decision": "DENIED",
		}).Info(output)

	case http.StatusOK:
		r.sysLogger.WithFields(logrus.Fields{
			"decision request source": req.RemoteAddr,
			"algorithm policy":        policies.Algorithm,
			"threshold policy":        policies.Threshold,
			"authorization decision":  "GRANTED",
		}).Info(output)

	default:
		r.sysLogger.WithFields(logrus.Fields{
			"package":                "router",
			"function":               "ServeHTTP",
			"algorithm":              policies.Algorithm,
			"threshold":              policies.Threshold,
			"authorization decision": "DENIED",
			"httpStatusCode":         resp.StatusCode,
		}).Error("unexpected trust algorithm response")
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.WriteHeader(resp.StatusCode)
	json.NewEncoder(w).Encode(output)
}

func (r *Router) ListenAndServeTLS() error {
	return r.frontend.ListenAndServeTLS("", "")
}

func (r *Router) CallTrustCalculationAlgorithm(sc scenario.Scenario, policies PapPolicyT) (*http.Response, error) {

	scenarioJSON, err := json.Marshal(sc)
	if err != nil {
		r.sysLogger.WithFields(logrus.Fields{
			"package":  "router",
			"function": "CallTrustCalculationAlgorithm",
			"comment":  "unable to marshal a scenario to a byte slice",
		}).Error(err)
		return nil, err
	}

	resp, err := r.caller.Client.Post(strings.Join(
		[]string{
			config.Config.Ta.TargetAddr,
			policies.Algorithm,
			policies.Threshold,
		},
		"/",
	),
		"application/json",
		bytes.NewBuffer(scenarioJSON),
	)

	if err != nil {
		r.sysLogger.WithFields(logrus.Fields{
			"package":   "router",
			"function":  "CallTrustCalculationAlgorithm",
			"algorithm": policies.Algorithm,
			"threshold": policies.Threshold,
		}).Error(err)
		return nil, err
	}

	return resp, nil
}

func (r *Router) GetPolicies(sni, action, username string) (PapPolicyT, error) {
	var policy PapPolicyT

	resp, err := r.caller.Client.Get(config.Config.Pap.TargetAddr)
	if err != nil {
		return PapPolicyT{}, err
	}

	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return PapPolicyT{}, err
	}

	return policy, nil
}
