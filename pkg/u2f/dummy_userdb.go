package u2f

import (
	"github.com/google/uuid"
	"time"
)

type UserDB struct {
}

func (u *UserDB) AuthenticateUser(userId string, authenticationSecret string) (success bool, sessionId string, validUntil time.Time) {
	sessionIdUuid, err := uuid.NewRandom()
	if err != nil {
		return false, "", time.Time{}
	}
	return true, sessionIdUuid.String(), time.Now().Add(24 * time.Hour)
}
