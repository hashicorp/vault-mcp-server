// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// writeServerCACert PEM-encodes the test server's certificate to a temp file so
// it can be used as a CA bundle via VAULT_CACERT.
func writeServerCACert(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}
	return caFile
}

// TestNewVaultClientHonorsCACert verifies that VAULT_CACERT lets the client
// verify a Vault listener presenting a private/self-signed certificate, and
// that without it verification still fails (i.e. we did not silently disable it).
func TestNewVaultClientHonorsCACert(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	caFile := writeServerCACert(t, srv)

	// Keep the test fast: no retry backoff on the expected TLS failure.
	t.Setenv("VAULT_MAX_RETRIES", "0")

	doRequest := func(sessionId string) error {
		c, err := NewVaultClient(sessionId, srv.URL, false, "test-token", "")
		if err != nil {
			t.Fatalf("NewVaultClient: %v", err)
		}
		req := c.NewRequest(http.MethodGet, "/v1/sys/health")
		resp, err := c.RawRequestWithContext(context.Background(), req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		return err
	}

	t.Run("without CA cert verification fails", func(t *testing.T) {
		t.Setenv(VaultCACert, "")
		if err := doRequest("no-ca"); err == nil {
			t.Fatal("expected TLS verification error against self-signed cert, got nil")
		}
	})

	t.Run("with CA cert verification succeeds", func(t *testing.T) {
		t.Setenv(VaultCACert, caFile)
		if err := doRequest("with-ca"); err != nil {
			t.Fatalf("expected success with VAULT_CACERT set, got: %v", err)
		}
	})
}
