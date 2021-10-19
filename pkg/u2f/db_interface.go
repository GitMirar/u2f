package u2f

import (
	"crypto/ecdsa"
)

type AccountDatabase interface {
	Register(identifier string, keyHandle []byte, pubKey []byte) (err error)
	GetPublicKey(identifier string) (pubKey *ecdsa.PublicKey, err error)
	GetKeyHandle(identifier string) (keyHandle []byte, err error)
}
