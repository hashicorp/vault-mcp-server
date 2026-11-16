// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/session"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	listBody = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
)

// testHTTPClient runs httpServerInit on a free loopback port and returns a
// request helper. The server is shut down when the test ends.
func startTestHTTPServer(t *testing.T, slot *session.Slot) func(method, body, sessionID string) *http.Response {
	t.Helper()
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:1")
	t.Setenv("VAULT_TOKEN", "test-token")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	require.NoError(t, ln.Close())

	logger := log.New()
	logger.SetLevel(log.PanicLevel)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- httpServerInit(ctx, NewServer("test", logger, nil), slot, logger, "127.0.0.1", port, "/mcp")
	}()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	httpClient := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
	url := "http://127.0.0.1:" + port + "/mcp"
	do := func(method, body, sessionID string) *http.Response {
		req, err := http.NewRequest(method, url, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if sessionID != "" {
			req.Header.Set("Mcp-Session-Id", sessionID)
		}
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp
	}

	// Wait for the listener; a server that is up answers 400 to a bad request.
	require.Eventually(t, func() bool {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+"/health", nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond)
	return do
}

// Without a slot (auth disabled) the server keeps no per-session state, so a
// session ID is only a label and DELETE does not invalidate it.
func TestHTTPServerStatelessWithoutSlot(t *testing.T) {
	do := startTestHTTPServer(t, nil)

	resp := do(http.MethodPost, initBody, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	sessionID := resp.Header.Get("Mcp-Session-Id")
	require.NotEmpty(t, sessionID)

	require.Equal(t, http.StatusOK, do(http.MethodPost, listBody, sessionID).StatusCode)
	require.Equal(t, http.StatusOK, do(http.MethodDelete, "", sessionID).StatusCode)
	require.Equal(t, http.StatusOK, do(http.MethodPost, listBody, sessionID).StatusCode)
}

func TestHTTPServerSingleSession(t *testing.T) {
	var ended atomic.Int32
	logger := log.New()
	logger.SetLevel(log.PanicLevel)
	slot := session.NewSlot(session.Config{}, func(string, string) { ended.Add(1) }, logger)
	do := startTestHTTPServer(t, slot)

	first := do(http.MethodPost, initBody, "").Header.Get("Mcp-Session-Id")
	require.NotEmpty(t, first)

	// A second client is refused while the first session exists.
	require.Equal(t, http.StatusConflict, do(http.MethodPost, initBody, "").StatusCode)
	require.Equal(t, http.StatusConflict, do(http.MethodPost, initBody, first).StatusCode)
	require.Equal(t, http.StatusOK, do(http.MethodPost, listBody, first).StatusCode, "first session is unaffected")

	// Requests that do not belong to a session are refused.
	require.Equal(t, http.StatusBadRequest, do(http.MethodPost, listBody, "").StatusCode)
	require.Equal(t, http.StatusNotFound, do(http.MethodPost, listBody, "mcp-session-unknown").StatusCode)

	// DELETE ends the session and runs the cleanup once; then a new client fits.
	require.Equal(t, http.StatusOK, do(http.MethodDelete, "", first).StatusCode)
	require.EqualValues(t, 1, ended.Load())
	require.Equal(t, http.StatusNotFound, do(http.MethodPost, listBody, first).StatusCode)

	second := do(http.MethodPost, initBody, "").Header.Get("Mcp-Session-Id")
	require.NotEmpty(t, second)
	require.NotEqual(t, first, second)
}

// The limit handler commits a session before the client sees the initialize
// response. A client that uses the new ID immediately must never get 404.
func TestHTTPServerInitializeCommitsBeforeClientUsesID(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.PanicLevel)
	slot := session.NewSlot(session.Config{}, nil, logger)
	do := startTestHTTPServer(t, slot)

	for i := 0; i < 50; i++ {
		id := do(http.MethodPost, initBody, "").Header.Get("Mcp-Session-Id")
		require.NotEmpty(t, id, "iteration %d", i)
		require.Equal(t, http.StatusOK, do(http.MethodPost, listBody, id).StatusCode, "iteration %d", i)
		require.Equal(t, http.StatusOK, do(http.MethodDelete, "", id).StatusCode, "iteration %d", i)
	}
}
