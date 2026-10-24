package auth

import "context"

type TokenExchanger interface {
	TokenExchange(ctx context.Context, subject, actor Token) (*DelegationJWT, error)
}
