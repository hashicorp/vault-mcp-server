// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"crypto/tls"
	"os"
	"strings"
)

type TLSConfig struct {
	CertFile string
	KeyFile  string
	Config   *tls.Config
}

// GetTLSConfigFromEnv loads TLS cert/key file paths from environment variables
func GetTLSConfigFromEnv() *TLSConfig {
	certFile := os.Getenv("MCP_TLS_CERT_FILE")
	keyFile := os.Getenv("MCP_TLS_KEY_FILE")

	if certFile == "" || keyFile == "" {
		return nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.X25519MLKEM768,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	return &TLSConfig{
		Config:   tlsConfig,
		CertFile: certFile,
		KeyFile:  keyFile,
	}
}

func IsLocalHost(host string) bool {
	h := strings.ToLower(host)
	return h == "localhost" ||
		h == "127.0.0.1" ||
		h == "::1" ||
		h == "[::1]" ||
		h == "0.0.0.0"
}
