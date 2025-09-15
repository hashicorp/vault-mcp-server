package client

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testCert = `-----BEGIN CERTIFICATE-----
MIICMzCCAdqgAwIBAgIUNZ9L86Xp9EuDH0/qyAesh599LXQwCgYIKoZIzj0EAwIw
eDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xEjAQBgNVBAoTCUhhc2hpQ29ycDEOMAwGA1UECxMFTm9tYWQx
GDAWBgNVBAMTD25vbWFkLmhhc2hpY29ycDAeFw0xNjExMTAxOTQ4MDBaFw0yMTEx
MDkxOTQ4MDBaMHgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw
FAYDVQQHEW1TYW4gRnJhbmNpc2NvMRIwEAYDVQQKEwlIYXNoaUNvcnAxDjAMBgNV
BAsTBU5vbWFkMRgwFgYDVQQDEw9ub21hZC5oYXNoaWNvcnAwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARfJmTdHzYIMPD8SK+kj5Gc79fmpOcg6wnb4JNVwCqWw9O+
uNdZJZWSi4Q/4HojM5FTSBqYxNgSrmY/o3oQrCPlo0IwQDAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUOjVq/BectnhcKn6EHUD4NJFm
/UAwCgYIKoZIzj0EAwIDRwAwRAIgTemDJGSGtcQPXLWKiQNw4SKO9wAPhn/WoKW4
Ln2ZUe8CIDsQswBQS7URbqnKYDye2Y4befJkr4fmhhmMQb2ex9A4
-----END CERTIFICATE-----`

	testKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKfQDg2EyoH7jrnlW2LoHQeKaiE7VeVX5DRb0E2Oh7AboAoGCCqGSM49
AwEHoUQDQgAEXyZk3R82CDDw/EivpI+RnO/X5qTnIOsJ2+CTVcAqlsPTvrjXWSWV
kouEP+B6IzORU0gamMTYEq5mP6N6EKwj5Q==
-----END EC PRIVATE KEY-----`
)

func TestTLSConfig(t *testing.T) {
	tmpCert, err := os.CreateTemp("", "test_cert_*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpCert.Name())

	tmpKey, err := os.CreateTemp("", "test_key_*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpKey.Name())

	_, err = tmpCert.WriteString(testCert)
	require.NoError(t, err)
	tmpCert.Close()

	_, err = tmpKey.WriteString(testKey)
	require.NoError(t, err)
	tmpKey.Close()

	os.Setenv("MCP_TLS_CERT_FILE", tmpCert.Name())
	os.Setenv("MCP_TLS_KEY_FILE", tmpKey.Name())
	defer func() {
		os.Unsetenv("MCP_TLS_CERT_FILE")
		os.Unsetenv("MCP_TLS_KEY_FILE")
	}()

	tlsConfig := GetTLSConfigFromEnv()
	require.NotNil(t, tlsConfig)
	require.Equal(t, tmpCert.Name(), tlsConfig.CertFile)
	require.Equal(t, tmpKey.Name(), tlsConfig.KeyFile)
	require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.Config.MinVersion)
}

func TestHTTPServerWithTLS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(server.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTLSConfigValidation(t *testing.T) {
	tests := []struct {
		name     string
		certFile string
		keyFile  string
		wantNil  bool
	}{
		{"both empty", "", "", true},
		{"cert only", "cert.pem", "", true},
		{"key only", "", "key.pem", true},
		{"both present", "cert.pem", "key.pem", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("MCP_TLS_CERT_FILE", tt.certFile)
			os.Setenv("MCP_TLS_KEY_FILE", tt.keyFile)
			defer func() {
				os.Unsetenv("MCP_TLS_CERT_FILE")
				os.Unsetenv("MCP_TLS_KEY_FILE")
			}()

			config := GetTLSConfigFromEnv()
			if tt.wantNil {
				require.Nil(t, config)
			} else {
				require.NotNil(t, config)
			}
		})
	}
}
