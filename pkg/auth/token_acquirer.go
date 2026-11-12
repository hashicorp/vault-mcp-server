package auth

import "context"

type TokenAcquirer interface {
	AcquireTokens(ctx context.Context) (*DelegationJWT, error)
}

type LoginResult struct {
	JWT *DelegationJWT
	Err error
}

// InteractiveTokenAcquirer starts login without waiting for user interaction.
type InteractiveTokenAcquirer interface {
	StartLogin(ctx context.Context) (string, <-chan LoginResult, error)
}
