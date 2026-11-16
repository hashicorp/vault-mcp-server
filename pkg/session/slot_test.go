// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package session

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func newTestSlot(onEnd EndFunc) *Slot {
	return newTestSlotWithConfig(Config{}, onEnd)
}

func newTestSlotWithConfig(cfg Config, onEnd EndFunc) *Slot {
	logger := log.New()
	logger.SetLevel(log.PanicLevel)
	return NewSlot(cfg, onEnd, logger)
}

func admit(t *testing.T, s *Slot, id string) {
	t.Helper()
	require.NoError(t, s.Reserve())
	require.NoError(t, s.Commit(id))
}

func TestSlotSingleSession(t *testing.T) {
	s := newTestSlot(nil)

	admit(t, s, "a")
	require.True(t, s.Has("a"))
	require.False(t, s.Has("b"))
	require.ErrorIs(t, s.Reserve(), ErrBusy)

	s.End("a", ReasonClientDelete)
	require.False(t, s.Has("a"))
	admit(t, s, "b")
}

func TestReservationHoldsSlot(t *testing.T) {
	s := newTestSlot(nil)

	require.NoError(t, s.Reserve())
	require.ErrorIs(t, s.Reserve(), ErrBusy)
	require.False(t, s.Has("a"), "a reservation is not a session yet")

	s.Cancel()
	s.Cancel() // idempotent
	require.NoError(t, s.Reserve())
	require.NoError(t, s.Commit("a"))

	s.Cancel() // no-op once committed
	require.True(t, s.Has("a"))
	require.Error(t, s.Commit("b"), "commit without a reservation")
}

func TestCommitErrorsReleaseSlot(t *testing.T) {
	s := newTestSlot(nil)
	require.NoError(t, s.Reserve())
	require.Error(t, s.Commit(""))
	admit(t, s, "a")
}

func TestConcurrentReservesOneWinner(t *testing.T) {
	s := newTestSlot(nil)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Reserve() == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, wins.Load())
}

func TestEndRunsCallbackOnceAndIsIdempotent(t *testing.T) {
	var calls atomic.Int32
	var gotID, gotReason string
	s := newTestSlot(func(id, reason string) {
		calls.Add(1)
		gotID, gotReason = id, reason
	})
	admit(t, s, "a")

	s.End("a", ReasonClientDelete)
	s.End("a", ReasonClientDelete)
	s.End("unknown", ReasonClientDelete)

	require.EqualValues(t, 1, calls.Load())
	require.Equal(t, "a", gotID)
	require.Equal(t, ReasonClientDelete, gotReason)
}

func TestEndWithWrongIDKeepsSession(t *testing.T) {
	s := newTestSlot(nil)
	admit(t, s, "a")
	s.End("other", ReasonClientDelete)
	require.True(t, s.Has("a"))
}

func TestSlotHeldUntilCallbackReturns(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	s := newTestSlot(func(string, string) {
		close(started)
		<-release
	})
	admit(t, s, "a")

	done := make(chan struct{})
	go func() { s.End("a", ReasonClientDelete); close(done) }()
	<-started

	require.False(t, s.Has("a"), "the ID is invalid as soon as the end starts")
	require.ErrorIs(t, s.Reserve(), ErrBusy, "slot stays taken during cleanup")

	close(release)
	<-done
	require.NoError(t, s.Reserve())
}

func TestShutdownEndsSessionAndRefusesNew(t *testing.T) {
	var calls atomic.Int32
	s := newTestSlot(func(string, string) { calls.Add(1) })
	admit(t, s, "a")

	s.Shutdown(ReasonShutdown)

	require.EqualValues(t, 1, calls.Load())
	require.False(t, s.Has("a"))
	require.ErrorIs(t, s.Reserve(), ErrClosed)
}

func TestShutdownWaitsForInFlightEnd(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	s := newTestSlot(func(string, string) {
		close(started)
		<-release
	})
	admit(t, s, "a")
	go s.End("a", ReasonClientDelete)
	<-started

	returned := make(chan struct{})
	go func() { s.Shutdown(ReasonShutdown); close(returned) }()

	select {
	case <-returned:
		t.Fatal("Shutdown returned while an End was still running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after the End finished")
	}
}

func TestPendingReservationCommitAfterShutdownFails(t *testing.T) {
	s := newTestSlot(nil)
	require.NoError(t, s.Reserve())

	s.Shutdown(ReasonShutdown)

	require.ErrorIs(t, s.Commit("a"), ErrClosed)
	require.False(t, s.Has("a"))
}

func TestSessionExpiry(t *testing.T) {
	const idleTimeout = 60 * time.Millisecond
	newSlot := func(ended chan<- string) *Slot {
		return newTestSlotWithConfig(Config{IdleTimeout: idleTimeout},
			func(id, reason string) { ended <- id + ":" + reason })
	}

	t.Run("an idle session expires and frees the slot", func(t *testing.T) {
		ended := make(chan string, 1)
		s := newSlot(ended)
		admit(t, s, "a")

		require.Equal(t, "a:"+ReasonIdle, <-ended)
		require.False(t, s.Has("a"))
		require.Eventually(t, func() bool { return s.Reserve() == nil }, time.Second, 5*time.Millisecond)
	})

	t.Run("activity keeps a session alive", func(t *testing.T) {
		ended := make(chan string, 1)
		s := newSlot(ended)
		admit(t, s, "a")

		for range 8 {
			time.Sleep(idleTimeout / 3)
			s.Touch("a")
		}
		require.True(t, s.Has("a"))
		require.Equal(t, "a:"+ReasonIdle, <-ended, "and expires once the activity stops")
	})

	t.Run("an old session's timer does not end the next one", func(t *testing.T) {
		ended := make(chan string, 2)
		s := newSlot(ended)
		admit(t, s, "a")
		s.End("a", ReasonClientDelete)
		require.Equal(t, "a:"+ReasonClientDelete, <-ended)
		admit(t, s, "b")

		time.Sleep(idleTimeout / 2)
		require.True(t, s.Has("b"), "a's timer has not ended b")
		s.End("b", ReasonClientDelete)
	})

	t.Run("expiry is off without a timeout", func(t *testing.T) {
		s := newTestSlot(nil)
		admit(t, s, "a")
		time.Sleep(30 * time.Millisecond)
		require.True(t, s.Has("a"))
	})
}

func TestSessionMaxLifetime(t *testing.T) {
	const maxLife = 150 * time.Millisecond

	t.Run("ends a session that stays active", func(t *testing.T) {
		ended := make(chan string, 1)
		s := newTestSlotWithConfig(Config{
			IdleTimeout: time.Minute,
			MaxLifetime: maxLife,
		}, func(id, reason string) { ended <- id + ":" + reason })
		admit(t, s, "a")

		stop := time.After(maxLife / 2)
	keepAlive:
		for {
			select {
			case <-stop:
				break keepAlive
			case <-time.After(10 * time.Millisecond):
				s.Touch("a")
			}
		}
		require.True(t, s.Has("a"), "still within the maximum lifetime")

		require.Equal(t, "a:"+ReasonMaxLifetime, <-ended)
		require.False(t, s.Has("a"))
		require.Eventually(t, func() bool { return s.Reserve() == nil }, time.Second, 5*time.Millisecond)
	})

	t.Run("works without idle expiry", func(t *testing.T) {
		ended := make(chan string, 1)
		s := newTestSlotWithConfig(Config{MaxLifetime: maxLife},
			func(id, reason string) { ended <- id + ":" + reason })
		admit(t, s, "a")
		require.Equal(t, "a:"+ReasonMaxLifetime, <-ended)
	})

	t.Run("an old session's timer does not end the next one", func(t *testing.T) {
		s := newTestSlotWithConfig(Config{MaxLifetime: maxLife}, nil)
		admit(t, s, "a")
		s.End("a", ReasonClientDelete)
		time.Sleep(maxLife / 3)
		admit(t, s, "b")

		time.Sleep(maxLife * 2 / 3) // past a's original deadline, before b's
		require.True(t, s.Has("b"))
	})

	t.Run("is off by default", func(t *testing.T) {
		s := newTestSlot(nil)
		admit(t, s, "a")
		time.Sleep(30 * time.Millisecond)
		require.True(t, s.Has("a"))
	})
}
