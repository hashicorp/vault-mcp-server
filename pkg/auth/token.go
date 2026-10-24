package auth

import "time"

type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    time.Time
	Subject      string
	Issuer       string
}
