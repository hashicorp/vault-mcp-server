package auth

import (
	"sync"
	"time"
)

type TokenStore struct {
	tokens sync.Map
}

func (s *TokenStore) Set(sessionID string, jwt *DelegationJWT) {
	s.tokens.Store(sessionID, jwt)
}

func (s *TokenStore) Get(sessionID string) (*DelegationJWT, bool) {
	value, ok := s.tokens.Load(sessionID)
	if !ok {
		return nil, false
	}

	jwt := value.(*DelegationJWT)
	if !jwt.Exp.IsZero() && !time.Now().Before(jwt.Exp) {
		return nil, false
	}
	return jwt, true
}

func (s *TokenStore) Delete(sessionID string) {
	s.tokens.Delete(sessionID)
}
