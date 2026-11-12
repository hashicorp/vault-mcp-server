package auth

import "context"

type IBMVerifySTS struct {
	Config  AuthConfig
	Subject Token
	Actor   Token
}

var _ TokenExchanger = (*IBMVerifySTS)(nil)

func (s *IBMVerifySTS) Exchange(ctx context.Context) (*DelegationJWT, error) {
	return exchangeTokens(ctx, s.Subject.AccessToken, s.Actor.AccessToken,
		s.Config.STSEndpoint, s.Config.STSClientID, s.Config.STSClientSecret,
		s.Config.STSAuthorizationDetails)
}
