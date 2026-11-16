// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package session

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	listBody = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
)

// fakeMCP mimics the library: initialize answers 200 with a new session ID.
type fakeMCP struct {
	nextID     atomic.Int32
	initStatus int // 0 means 200
	noIDOnInit bool
	initBodies []string
}

func (f *fakeMCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"initialize"`) {
			f.initBodies = append(f.initBodies, string(body))
			status := f.initStatus
			if status == 0 {
				status = http.StatusOK
			}
			if !f.noIDOnInit && status < 300 {
				w.Header().Set(HeaderSessionID, "s"+string(rune('0'+f.nextID.Add(1))))
			}
			w.WriteHeader(status)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func newLimitHandlerTest(f *fakeMCP) (*SessionLimitHandler, *Slot) {
	slot := newTestSlot(nil)
	return NewSessionLimitHandler(slot, f, nil), slot
}

func do(g http.Handler, method, body, sessionID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/mcp", strings.NewReader(body))
	if sessionID != "" {
		req.Header.Set(HeaderSessionID, sessionID)
	}
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return rec
}

func TestLimitHandlerSingleSessionLifecycle(t *testing.T) {
	f := &fakeMCP{}
	g, slot := newLimitHandlerTest(f)

	rec := do(g, http.MethodPost, initBody, "")
	require.Equal(t, http.StatusOK, rec.Code)
	id := rec.Header().Get(HeaderSessionID)
	require.Equal(t, "s1", id)
	require.True(t, slot.Has(id))

	// The inner handler sees the full initialize body.
	require.Equal(t, []string{initBody}, f.initBodies)

	require.Equal(t, http.StatusOK, do(g, http.MethodPost, listBody, id).Code)

	// A second initialize is refused, with or without an existing ID.
	rec = do(g, http.MethodPost, initBody, "")
	require.Equal(t, http.StatusConflict, rec.Code)
	require.Contains(t, rec.Body.String(), "already active")
	require.Equal(t, http.StatusConflict, do(g, http.MethodPost, initBody, id).Code)
	require.Len(t, f.initBodies, 1, "rejected initializes never reach the library")

	require.Equal(t, http.StatusOK, do(g, http.MethodDelete, "", id).Code)
	require.False(t, slot.Has(id))
	require.Equal(t, http.StatusNotFound, do(g, http.MethodPost, listBody, id).Code)

	// The slot is free again.
	require.Equal(t, http.StatusOK, do(g, http.MethodPost, initBody, "").Code)
	require.True(t, slot.Has("s2"))
}

func TestLimitHandlerFailedInitializeReleasesSlot(t *testing.T) {
	f := &fakeMCP{initStatus: http.StatusBadRequest}
	g, slot := newLimitHandlerTest(f)

	require.Equal(t, http.StatusBadRequest, do(g, http.MethodPost, initBody, "").Code)
	require.NoError(t, slot.Reserve(), "the slot was released")
	slot.Cancel()

	f.initStatus = 0
	require.Equal(t, http.StatusOK, do(g, http.MethodPost, initBody, "").Code)
}

func TestLimitHandlerInitializeWithoutIDIsNotAdmitted(t *testing.T) {
	f := &fakeMCP{noIDOnInit: true}
	g, slot := newLimitHandlerTest(f)

	require.Equal(t, http.StatusOK, do(g, http.MethodPost, initBody, "").Code)
	require.NoError(t, slot.Reserve(), "the slot was released")
}

func TestLimitHandlerOversizedBodyIsRejected(t *testing.T) {
	g, slot := newLimitHandlerTest(&fakeMCP{})

	big := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":"` + strings.Repeat("a", maxPeekBytes) + `"}`
	require.Equal(t, http.StatusRequestEntityTooLarge, do(g, http.MethodPost, big, "").Code)
	require.NoError(t, slot.Reserve(), "the slot was never taken")
}

func TestLimitHandlerRouting(t *testing.T) {
	g, _ := newLimitHandlerTest(&fakeMCP{})

	require.Equal(t, http.StatusBadRequest, do(g, http.MethodPost, listBody, "").Code, "no ID")
	require.Equal(t, http.StatusBadRequest, do(g, http.MethodGet, "", "").Code, "GET without ID")
	require.Equal(t, http.StatusNotFound, do(g, http.MethodPost, listBody, "nope").Code, "unknown ID")
	require.Equal(t, http.StatusNotFound, do(g, http.MethodDelete, "", "nope").Code, "DELETE unknown ID")
}

func TestLimitHandlerDeleteRunsOnEnd(t *testing.T) {
	var ended []string
	slot := newTestSlot(func(id, reason string) { ended = append(ended, id+":"+reason) })
	g := NewSessionLimitHandler(slot, &fakeMCP{}, nil)

	id := do(g, http.MethodPost, initBody, "").Header().Get(HeaderSessionID)
	require.Equal(t, http.StatusOK, do(g, http.MethodDelete, "", id).Code)

	require.Equal(t, []string{"s1:" + ReasonClientDelete}, ended)
}

func TestLimitHandlerShutdownRejectsInitialize(t *testing.T) {
	g, slot := newLimitHandlerTest(&fakeMCP{})
	slot.Shutdown(ReasonShutdown)
	require.Equal(t, http.StatusServiceUnavailable, do(g, http.MethodPost, initBody, "").Code)
}

func TestLimitHandlerRequestsKeepSessionAlive(t *testing.T) {
	const timeout = 80 * time.Millisecond
	slot := newTestSlotWithConfig(Config{IdleTimeout: timeout}, nil)
	h := NewSessionLimitHandler(slot, &fakeMCP{}, nil)

	id := do(h, http.MethodPost, initBody, "").Header().Get(HeaderSessionID)
	for range 8 {
		time.Sleep(timeout / 4)
		require.Equal(t, http.StatusOK, do(h, http.MethodPost, listBody, id).Code)
	}

	require.Eventually(t, func() bool { return !slot.Has(id) }, 2*time.Second, 10*time.Millisecond,
		"the session expires once requests stop")
	require.Equal(t, http.StatusNotFound, do(h, http.MethodPost, listBody, id).Code)
}
