package u2f

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"io/ioutil"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/idna"
)

// TODO: implement garbage collection for timedout registration state
type Api struct {
	appId                 string
	db                    KeyDatabase
	secureCookie          *securecookie.SecureCookie
	registrationState     map[uuid.UUID]time.Time
	registrationStateLock sync.RWMutex
	authState             map[string]struct {
		T         time.Time
		Challenge []byte
	}
	authStateLock                sync.RWMutex
	authCompleteCallback         AuthenticationCompletedCallback
	registrationCompleteCallback RegistrationCompletedCallback
	authCallback                 UserAuthenticationCallback
	registrationCallback         RegistrationCallback
	exposeRegisterEndpoint       bool
}

const (
	U2fVersion = "U2F_V2"
	ApiTimeout = 10 * time.Second
	U2fTokenId = "U2FTID"
)

const (
	U2F_STATUS_SUCCESS = 0
	U2F_STATUS_ERROR   = 1
	U2F_STATUS_FAILURE = 2
)

func NewU2FApi(server *mux.Router,
	db KeyDatabase,
	appId string,
	exposeRegisterEndpoint bool,
	cookieHashKey [32]byte,
	cookieBlockKey [32]byte,
	authCallback UserAuthenticationCallback,
	authCompletedCallback AuthenticationCompletedCallback,
	registrationCallback RegistrationCallback,
	registrationCompletedCallback RegistrationCompletedCallback) (a *Api) {
	a = &Api{
		db:                    db,
		appId:                 appId,
		registrationState:     map[uuid.UUID]time.Time{},
		registrationStateLock: sync.RWMutex{},
		authState: map[string]struct {
			T         time.Time
			Challenge []byte
		}{},
		authStateLock:                sync.RWMutex{},
		authCompleteCallback:         authCompletedCallback,
		registrationCompleteCallback: registrationCompletedCallback,
		registrationCallback:         registrationCallback,
		authCallback:                 authCallback,
		exposeRegisterEndpoint:       exposeRegisterEndpoint,
		secureCookie:                 securecookie.New(cookieHashKey[:], cookieBlockKey[:]),
	}
	if a.exposeRegisterEndpoint {
		server.HandleFunc("/auth/register/begin", a.RegisterBegin)
		server.HandleFunc("/auth/register/complete", a.RegisterComplete)
	}
	server.HandleFunc("/auth/authenticate/begin", a.AuthenticateBegin)
	server.HandleFunc("/auth/authenticate/complete", a.AuthenticateComplete)
	return a
}

func (a *Api) gc() {
	/*
		Garbage collect old state.
	*/
	a.authStateLock.Lock()
	for k, v := range a.authState {
		if time.Now().After(v.T.Add(ApiTimeout)) {
			delete(a.authState, k)
		}
	}
	a.authStateLock.Unlock()
	a.registrationStateLock.Lock()
	for k, v := range a.registrationState {
		if time.Now().After(v.Add(ApiTimeout)) {
			delete(a.registrationState, k)
		}
	}
	a.registrationStateLock.Unlock()
}

func (a *Api) RegisterBegin(writer http.ResponseWriter, request *http.Request) {
	a.gc()
	a.registrationStateLock.Lock()
	defer a.registrationStateLock.Unlock()
	requestData, err := ioutil.ReadAll(request.Body)
	if err != nil {
		requestData = nil
	}
	if !a.registrationCallback(requestData, request) {
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	userId, err := uuid.NewRandom()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	userIdB, err := userId.MarshalBinary()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	a.registrationState[userId] = time.Now()
	registrationData := RegistrationData{
		Challenge: WebSafeB64Encode(userIdB),
		AppId:     a.appId,
		Version:   U2fVersion,
	}
	response, _ := json.Marshal(registrationData)
	_, _ = writer.Write(response)
}

func (a *Api) RegisterComplete(writer http.ResponseWriter, request *http.Request) {
	a.gc()
	requestData, _ := ioutil.ReadAll(request.Body)
	r, err := ParseRegistrationResponse(requestData)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	userIdB, err := WebSafeB64Decode(r.ClientData.Challenge)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	userId, err := uuid.FromBytes(userIdB)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if t, ok := a.registrationState[userId]; ok {
		if time.Now().After(t.Add(ApiTimeout)) {
			http.Error(writer, http.StatusText(http.StatusRequestTimeout), http.StatusRequestTimeout)
			return
		}

		certificate, err := x509.ParseCertificate(r.Cert)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return

		}

		AppIdIdna, err := idna.ToASCII(r.ClientData.Origin)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		AppParam := sha256.Sum256([]byte(AppIdIdna))
		ClientParam := sha256.Sum256(r.ClientDataRaw)
		signBuffer := append([]byte("\x00"), AppParam[:]...)
		signBuffer = append(signBuffer, ClientParam[:]...)
		signBuffer = append(signBuffer, r.KeyHandle[:]...)
		signBuffer = append(signBuffer, r.PubKey[:]...)
		err = certificate.CheckSignature(x509.ECDSAWithSHA256, signBuffer, r.Signature)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusNotAcceptable), http.StatusNotAcceptable)
			return
		}

		if err := a.db.Register(userId.String(), r.KeyHandle, r.PubKey); err != nil {
			http.Error(writer, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}

		if !a.registrationCompleteCallback(writer, request, userId.String()) {
			delete(a.registrationState, userId)
			http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		delete(a.registrationState, userId)
	} else {
		http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
}

func (a *Api) AuthenticateBegin(writer http.ResponseWriter, request *http.Request) {
	a.gc()
	a.authStateLock.Lock()
	defer a.authStateLock.Unlock()
	requestData, err := ioutil.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	authSuccessful, keyIdentifier := a.authCallback(requestData, request)
	if !authSuccessful {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	keyHandle, err := a.db.GetKeyHandle(keyIdentifier)
	if err != nil {
		a.authCompleteCallback(U2F_STATUS_ERROR, writer, request, keyIdentifier)
		return
	}

	challenge, err := uuid.NewRandom()
	if err != nil {
		a.authCompleteCallback(U2F_STATUS_ERROR, writer, request, keyIdentifier)
		return
	}

	bChallenger, err := challenge.MarshalBinary()
	if err != nil {
		a.authCompleteCallback(U2F_STATUS_ERROR, writer, request, keyIdentifier)
		return
	}

	if _, ok := a.authState[keyIdentifier]; !ok {
		a.authState[keyIdentifier] = struct {
			T         time.Time
			Challenge []byte
		}{T: time.Now(), Challenge: bChallenger}
	} else {
		a.authCompleteCallback(U2F_STATUS_ERROR, writer, request, keyIdentifier)
		return
	}

	encoded, err := a.secureCookie.Encode(U2fTokenId, keyIdentifier)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{
		Name:     U2fTokenId,
		Value:    encoded,
		Path:     "/auth/",
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Now().Add(ApiTimeout),
	}
	http.SetCookie(writer, cookie)

	signRequestData := SignRequestData{
		KeyHandle: WebSafeB64Encode(keyHandle),
		AppId:     a.appId,
		Version:   U2fVersion,
		Challenge: WebSafeB64Encode(bChallenger),
	}
	response, _ := json.Marshal(signRequestData)
	_, _ = writer.Write(response)
}

func (a *Api) AuthenticateComplete(writer http.ResponseWriter, request *http.Request) {
	a.gc()
	a.authStateLock.Lock()
	defer a.authStateLock.Unlock()
	requestData, _ := ioutil.ReadAll(request.Body)
	if r, err := ParseSignatureResponse(requestData); err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else {
		var keyIdentifier string
		if cookie, err := request.Cookie(U2fTokenId); err == nil {
			if err = a.secureCookie.Decode(U2fTokenId, cookie.Value, &keyIdentifier); err != nil {
				http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		var bIssuedChallenge []byte
		if s, ok := a.authState[keyIdentifier]; ok {
			if time.Now().After(s.T.Add(ApiTimeout)) {
				a.authCompleteCallback(U2F_STATUS_ERROR, writer, request, keyIdentifier)
				delete(a.authState, keyIdentifier)
				return
			}
			bIssuedChallenge = s.Challenge
			delete(a.authState, keyIdentifier)
		} else {
			// we didn't see a call to /auth/authenticate/begin for this user id
			a.authCompleteCallback(U2F_STATUS_ERROR, writer, request, keyIdentifier)
			return
		}

		bChallenge, err := WebSafeB64Decode(r.ClientData.Challenge)
		if err != nil {
			a.authCompleteCallback(U2F_STATUS_ERROR, writer, request, keyIdentifier)
			return
		}
		if string(bChallenge) != string(bIssuedChallenge) {
			// The signed challenge does not match the challenge on record for this authentication.
			// Possibly this is a replay attack.
			a.authCompleteCallback(U2F_STATUS_ERROR, writer, request, keyIdentifier)
			return
		}

		pubKey, err := a.db.GetPublicKey(keyIdentifier)
		if err != nil {
			a.authCompleteCallback(U2F_STATUS_ERROR, writer, request, keyIdentifier)
			return
		}

		AppIdIdna, err := idna.ToASCII(r.ClientData.Origin)
		if err != nil {
			a.authCompleteCallback(U2F_STATUS_ERROR, writer, request, keyIdentifier)
			return
		}
		AppParam := sha256.Sum256([]byte(AppIdIdna))
		UserPresence := byte(0)
		if r.SignatureData.UserPresence {
			UserPresence = byte(1)
		}
		SignatureCounter := make([]byte, 4)
		binary.BigEndian.PutUint32(SignatureCounter, uint32(r.SignatureData.Counter))
		ClientParam := sha256.Sum256(r.ClientDataRaw)
		signBuffer := append([]byte(""), AppParam[:]...)
		signBuffer = append(signBuffer, UserPresence)
		signBuffer = append(signBuffer, SignatureCounter[:]...)
		signBuffer = append(signBuffer, ClientParam[:]...)

		var esig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(r.SignatureData.Signature, &esig); err != nil {
			a.authCompleteCallback(U2F_STATUS_ERROR, writer, request, keyIdentifier)
			return
		}
		hashBuf := sha256.Sum256(signBuffer)
		if ecdsa.Verify(pubKey, hashBuf[:], esig.R, esig.S) {
			a.authCompleteCallback(U2F_STATUS_SUCCESS, writer, request, keyIdentifier)
			return
		} else {
			a.authCompleteCallback(U2F_STATUS_FAILURE, writer, request, keyIdentifier)
			return
		}
	}
}
