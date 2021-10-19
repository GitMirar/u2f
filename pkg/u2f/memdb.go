package u2f

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"sync"
)

const (
	DerPubKeyPrefix = "3059301306072a8648ce3d020106082a8648ce3d030107034200"
)

type MemDB struct {
	db   map[string]*MemDBEntry
	lock sync.RWMutex
}

type MemDBEntry struct {
	PubKey    []byte
	KeyHandle []byte
}

func (m *MemDB) Register(identifier string, keyHandle []byte, pubKey []byte) (err error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if _, ok := m.db[identifier]; !ok {
		m.db[identifier] = &MemDBEntry{
			PubKey:    pubKey,
			KeyHandle: keyHandle,
		}
		log.Infof("Registered new key for id %s", identifier)
	} else {
		return errors.New("identifier already registered")
	}
	return nil
}

func (m *MemDB) GetKeyHandle(identifier string) (keyHandle []byte, err error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if data, ok := m.db[identifier]; ok {
		return data.KeyHandle, nil
	} else {
		return nil, errors.New(fmt.Sprintf("Could not find a key handle for the identifier %v", identifier))
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
		return nil, errors.New(fmt.Sprintf("Could not find a key handle for the identifier %v", identifier))
	}
}

func NewMemDB() *MemDB {
	return &MemDB{
		db:   map[string]*MemDBEntry{},
		lock: sync.RWMutex{},
	}
}
