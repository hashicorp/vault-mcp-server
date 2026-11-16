// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package session limits the server to one MCP session at a time.
//
// Auth state is process-wide, so a second concurrent session would share and
// could wipe the first one's credentials. Slot is the single place that
// admits a session and ends it. It is deliberately not a registry: when auth
// becomes per-session, replace it with one keyed by session ID.
package session

import (
	"errors"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	// ErrBusy means a session is active, starting, or still being ended.
	ErrBusy = errors.New("session: another session is already active")

	// ErrClosed means Shutdown has run; no new sessions are admitted.
	ErrClosed = errors.New("session: shut down")

	errNotReserved = errors.New("session: no reservation to commit")
)

// Reasons a session ends, used in logs and passed to the end callback.
const (
	ReasonClientDelete = "client_delete"
	ReasonIdle         = "idle"
	ReasonMaxLifetime  = "max_lifetime"
	ReasonShutdown     = "shutdown"
)

// Config sets when a session expires. Expiry is what frees the slot of a
// client that vanished without sending DELETE.
type Config struct {
	// IdleTimeout ends a session that has had no request for this long.
	// Activity is recorded when a request starts and when it ends, not while
	// it is in flight, so a request (such as an open SSE stream) that runs
	// longer than this can see its session expire. Set it comfortably above
	// the longest expected request. Zero disables it.
	IdleTimeout time.Duration
	// MaxLifetime ends a session this long after it started, whatever its
	// activity, so a busy session still has to sign in again regularly.
	// Zero disables it.
	MaxLifetime time.Duration
}

// EndFunc releases everything the session owns. It runs once per session.
type EndFunc func(id, reason string)

type state int

const (
	free     state = iota
	reserved       // an initialize is in flight; its session ID is not known yet
	active
	ending // the end callback is running
)

// Slot holds the single session. It is safe for concurrent use. One Slot is
// created per server process and reused for every session in turn.
type Slot struct {
	cfg   Config
	onEnd EndFunc
	log   log.FieldLogger

	mu      sync.Mutex
	state   state
	id      string
	started time.Time
	// closed is set by Shutdown and never cleared. Reserve and Commit refuse
	// once it is set, so no session can start while the process is shutting down.
	closed bool
	// lastActive and the timers are only set while state == active and the
	// matching expiry is enabled.
	lastActive time.Time
	timer      *time.Timer
	lifeTimer  *time.Timer // ends the session at MaxLifetime
	// endDone exists only while state == ending. finish closes it (nothing is
	// ever sent on it) once the end callback has returned, which wakes anyone
	// blocked on <-endDone. Shutdown uses it to wait for an end that another
	// goroutine started, such as an idle or lifetime timer, so the process
	// does not exit in the middle of a token revocation.
	endDone chan struct{}
}

// NewSlot creates an empty Slot. onEnd may be nil. Each expiry is off unless
// its timeout in cfg is set.
func NewSlot(cfg Config, onEnd EndFunc, logger log.FieldLogger) *Slot {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &Slot{cfg: cfg, onEnd: onEnd, log: logger}
}

// Reserve takes the slot for an initialize that is about to run. In HTTP the
// session ID only exists after the library handles initialize, so the slot is
// taken first and bound to the ID by Commit. This keeps "check, then admit"
// atomic when initializes race. Every successful Reserve must be followed by
// Commit, or by Cancel if Commit was never called.
func (s *Slot) Reserve() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return ErrClosed
	case s.state != free:
		return ErrBusy
	}
	s.state = reserved
	return nil
}

// Commit binds the reserved slot to the session ID. On any error the slot is
// released.
func (s *Slot) Commit(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != reserved {
		return errNotReserved
	}
	switch {
	case s.closed:
		s.state = free
		return ErrClosed
	case id == "":
		s.state = free
		return errors.New("session: empty session ID")
	}
	now := time.Now()
	s.state, s.id, s.started = active, id, now
	if s.cfg.IdleTimeout > 0 {
		s.lastActive = now
		s.timer = time.AfterFunc(s.cfg.IdleTimeout, func() { s.expire(id) })
	}
	if s.cfg.MaxLifetime > 0 {
		s.lifeTimer = time.AfterFunc(s.cfg.MaxLifetime, func() { s.End(id, ReasonMaxLifetime) })
	}
	s.log.Info("Session started")
	return nil
}

// Cancel releases a reservation that was never committed.
func (s *Slot) Cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == reserved {
		s.state = free
	}
}

// Has reports whether id is the active session. It is false as soon as the
// session starts ending.
func (s *Slot) Has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == active && s.id == id
}

// Touch records activity on the active session, which postpones its expiry.
func (s *Slot) Touch(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == active && s.id == id {
		s.lastActive = time.Now()
	}
}

// expire runs when the idle timer fires. Touch only records the time, so the
// session ends only if it has really been idle for IdleTimeout; otherwise the
// timer is re-armed for the remainder.
func (s *Slot) expire(id string) {
	limit := s.cfg.IdleTimeout

	s.mu.Lock()
	if s.state != active || s.id != id {
		s.mu.Unlock()
		return
	}
	if idle := time.Since(s.lastActive); idle < limit {
		s.timer.Reset(limit - idle)
		s.mu.Unlock()
		return
	}
	started, done := s.beginEndLocked()
	s.mu.Unlock()

	s.finish(id, ReasonIdle, started, done)
}

// End ends the session if id is the active one, and returns after the end
// callback has finished. The ID stops being valid immediately, but the slot
// stays taken until the callback returns: a new session must not start while
// the old one's credentials are still being revoked. End is idempotent.
func (s *Slot) End(id, reason string) {
	s.mu.Lock()
	if s.state != active || s.id != id {
		s.mu.Unlock()
		return
	}
	started, done := s.beginEndLocked()
	s.mu.Unlock()

	s.finish(id, reason, started, done)
}

// beginEndLocked moves the active session to ending. s.mu must be held.
func (s *Slot) beginEndLocked() (started time.Time, done chan struct{}) {
	s.state = ending
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if s.lifeTimer != nil {
		s.lifeTimer.Stop()
		s.lifeTimer = nil
	}
	done = make(chan struct{})
	s.endDone = done
	return s.started, done
}

func (s *Slot) finish(id, reason string, started time.Time, done chan struct{}) {
	entry := s.log.WithField("reason", reason)
	entry.Info("Session ending")
	if s.onEnd != nil {
		s.onEnd(id, reason)
	}

	s.mu.Lock()
	s.state, s.id, s.endDone = free, "", nil
	s.mu.Unlock()
	close(done)
	entry.WithField("lifetime", time.Since(started).Round(time.Second).String()).Info("Session ended")
}

// Shutdown ends the active session, waits for any end already in progress,
// and refuses new sessions from then on.
func (s *Slot) Shutdown(reason string) {
	s.mu.Lock()
	s.closed = true
	id, isActive := s.id, s.state == active
	s.mu.Unlock()

	if isActive {
		s.End(id, reason)
	}

	s.mu.Lock()
	inFlight := s.endDone
	s.mu.Unlock()
	if inFlight != nil {
		// Another goroutine is ending the session (DELETE, a timer, or a timer
		// that fired between the check above and our End). Wait for its cleanup.
		<-inFlight
	}
}
