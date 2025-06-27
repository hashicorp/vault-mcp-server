package main

import (
	"fmt"
	"github.com/google/uuid"
	"strings"
)

type VaultStatefulSessionIdManager struct{}

const idPrefix = "mcp-session-"

func (s *VaultStatefulSessionIdManager) Generate() string {
	sessionId := idPrefix + uuid.New().String()
	/*
		_, err := newVaultClient(sessionId)
		if err != nil {
			return ""
		}
	*/
	return sessionId
}
func (s *VaultStatefulSessionIdManager) Validate(sessionID string) (isTerminated bool, err error) {
	// validate the session id is a valid uuid
	if !strings.HasPrefix(sessionID, idPrefix) {
		return false, fmt.Errorf("invalid session id: %s", sessionID)
	}
	if _, err := uuid.Parse(sessionID[len(idPrefix):]); err != nil {
		return false, fmt.Errorf("invalid session id: %s", sessionID)
	}
	return false, nil
}
func (s *VaultStatefulSessionIdManager) Terminate(sessionID string) (isNotAllowed bool, err error) {
	//deleteVaultClient(sessionID)
	return false, nil
}
