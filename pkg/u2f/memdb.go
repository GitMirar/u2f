package u2f

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

const (
	DerPubKeyPrefix = "3059301306072a8648ce3d020106082a8648ce3d030107034200"
)

type MemDB struct {
	db   map[string]*RegistrationResponse
	lock sync.RWMutex
}

func (m *MemDB) Register(identifier string, data *RegistrationResponse) (err error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if _, ok := m.db[identifier]; !ok {
		m.db[identifier] = data
	} else {
		return errors.New("identifier already registered")
	}
	return nil
}

func (m *MemDB) GetCertificate(identifier string) (cert *x509.Certificate, err error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if data, ok := m.db[identifier]; ok {
		if cert, err = x509.ParseCertificate(data.Cert); ok {
			return cert, nil
		} else {
			return nil, errors.New(fmt.Sprintf("certificate data corrupted (%v)", err))
		}
	} else {
		return nil, errors.New(fmt.Sprintf("could not find a certificate for the identifier %v", identifier))
	}
}

func (m *MemDB) GetKeyHandle(identifier string) (keyHandle []byte, err error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if data, ok := m.db[identifier]; ok {
		return data.KeyHandle, nil
	} else {
		return nil, errors.New(fmt.Sprintf("could not find a key handle for the identifier %v", identifier))
	}
}

func (m *MemDB) GetPublicKey(identifier string) (pubKey *ecdsa.PublicKey, err error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if data, ok := m.db[identifier]; ok {
		prefix, err := hex.DecodeString(DerPubKeyPrefix)
		if err != nil {
			return nil, err
		}
		pubKey, err := x509.ParsePKIXPublicKey(append(prefix, data.PubKey[:]...))
		return pubKey.(*ecdsa.PublicKey), err
	} else {
		return nil, errors.New(fmt.Sprintf("could not find a key handle for the identifier %v", identifier))
	}
}

func NewMemDB() *MemDB {
	return &MemDB{
		db:   map[string]*RegistrationResponse{},
		lock: sync.RWMutex{},
	}
}
