// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// maxPeekBytes bounds the body the handler reads to find the JSON-RPC method.
const maxPeekBytes = 1 << 20

// HeaderSessionID is the MCP session header (streamable HTTP transport).
const HeaderSessionID = server.HeaderKeySessionID

// SessionLimitHandler is HTTP middleware that limits the server to one MCP
// session. It wraps the mcp-go streamable HTTP handler and drives the Slot
// from the HTTP traffic:
//
//	POST initialize          -> Reserve; ErrBusy -> 409. After the library
//	                            answers, Commit if the response carries an
//	                            Mcp-Session-Id, else Cancel.
//	any other request        -> no ID: 400 (a session must start with
//	                            initialize); unknown or ended ID: 404.
//	DELETE with a known ID   -> pass through, then end the session.
//	any request with a known ID counts as activity for the Slot's expiry timer.
//
// Place it directly around the mcp-go handler, inside the CORS/origin
// security wrapper, so rejected cross-origin requests never reach it.
type SessionLimitHandler struct {
	slot *Slot
	next http.Handler
	log  log.FieldLogger
}

// NewSessionLimitHandler wraps next (the mcp-go StreamableHTTPServer).
func NewSessionLimitHandler(slot *Slot, next http.Handler, logger log.FieldLogger) *SessionLimitHandler {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &SessionLimitHandler{slot: slot, next: next, log: logger}
}

// ServeHTTP implements http.Handler.
func (h *SessionLimitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.next.ServeHTTP(w, r)
		return
	}

	if r.Method == http.MethodPost {
		isInit, err := peekIsInitialize(r)
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		case err != nil:
			http.Error(w, "Could not read request body", http.StatusBadRequest)
			return
		}
		if isInit {
			// An initialize always starts a new session: the library ignores
			// any Mcp-Session-Id on it and generates a fresh one.
			h.admit(w, r)
			return
		}
	}

	id := r.Header.Get(HeaderSessionID)
	if id == "" {
		// A GET without an ID would make the library register a session the
		// registry does not know about.
		http.Error(w, "Missing "+HeaderSessionID+" header: start a session with initialize", http.StatusBadRequest)
		return
	}
	if !h.slot.Has(id) {
		h.log.WithField("method", r.Method).Info("Request for unknown or ended session rejected (404)")
		http.Error(w, "Session not found or expired: send a new initialize request", http.StatusNotFound)
		return
	}

	h.slot.Touch(id)
	defer h.slot.Touch(id) // a long request counts as activity until it ends

	h.next.ServeHTTP(w, r)
	if r.Method == http.MethodDelete {
		// End even if the library did not answer 2xx: the client has said it
		// is done, so its credentials must go.
		h.slot.End(id, ReasonClientDelete)
	}
}

// admit handles an initialize request: reserve a slot, let the library
// create the session, and commit the reservation with the new ID.
func (h *SessionLimitHandler) admit(w http.ResponseWriter, r *http.Request) {
	err := h.slot.Reserve()
	switch {
	case errors.Is(err, ErrBusy):
		h.log.WithField("remote", r.RemoteAddr).Warn("initialize rejected: another session is active (409)")
		http.Error(w, "Another MCP session is already active on this server. Only one session is allowed at a time; "+
			"close the other client and try again.", http.StatusConflict)
		return
	case errors.Is(err, ErrClosed):
		http.Error(w, "Server is shutting down", http.StatusServiceUnavailable)
		return
	case err != nil:
		h.log.WithError(err).Error("initialize rejected: could not reserve session")
		http.Error(w, "Could not start a session", http.StatusInternalServerError)
		return
	}

	// Release the reservation if initialize did not produce a session (error
	// response, or the handler panicked). Otherwise the slot would stay
	// reserved and every later initialize would get 409 until restart. This is
	// a no-op once Commit has run.
	defer h.slot.Cancel()

	h.next.ServeHTTP(w, r)

	// We infer success from the Mcp-Session-Id response header. Known limitation:
	// the library also sets that header when initialize is answered with a
	// JSON-RPC error (for example malformed params), so such a request takes
	// the slot until it expires.
	if sid := w.Header().Get(HeaderSessionID); sid != "" {
		if err := h.slot.Commit(sid); err != nil {
			h.log.WithError(err).Warn("Could not admit session after initialize")
		}
	}
}

// peekIsInitialize reads the JSON-RPC method from a POST body and puts the
// body back for the next handler.
// In HTTP mode this tells whether a POST is the JSON-RPC initialize request,
// the only request allowed to start a session without an Mcp-Session-Id.
func peekIsInitialize(r *http.Request) (bool, error) {
	if r.Body == nil {
		return false, nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxPeekBytes))
	_ = r.Body.Close()
	if err != nil {
		return false, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	var msg struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(body, &msg) != nil {
		return false, nil
	}
	return msg.Method == string(mcp.MethodInitialize), nil
}
