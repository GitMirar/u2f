package u2f

import "time"

type AuthenticationRequest struct {
	UserId               string `json:"user_id"`
	AuthenticationSecret string `json:"authentication_secret"`
}

type UserDatabase interface {
	AuthenticateUser(userId string, authenticationSecret string) (success bool, sessionId string, validUntil time.Time)
	EnableSession(sessionId string) (err error)
}
