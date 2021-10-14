package u2f

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"golang.org/x/net/idna"
)

// TODO: implement garbage collection for timedout registration state
type Api struct {
	appId                 string
	db                    AccountDatabase
	userDb                UserDatabase
	registrationState     map[uuid.UUID]time.Time
	registrationStateLock sync.RWMutex
	secureCookie          *securecookie.SecureCookie
}

const (
	U2fVersion      = "U2F_V2"
	RegisterTimeout = 30 * time.Second
	U2fTokenId      = "SFID"
)

func NewU2FApi(server *HTTPServer, db AccountDatabase, appId string, hashKey [32]byte, blockKey [32]byte) (a *Api) {
	a = &Api{
		db:                    db,
		appId:                 appId,
		registrationState:     map[uuid.UUID]time.Time{},
		registrationStateLock: sync.RWMutex{},
		secureCookie:          securecookie.New(hashKey[:], blockKey[:]),
	}
	server.HandleFunc("/api/register/begin", a.RegisterBegin)
	server.HandleFunc("/api/register/complete", a.RegisterComplete)
	server.HandleFunc("/api/authenticate/begin", a.AuthenticateBegin)
	server.HandleFunc("/api/authenticate/complete", a.AuthenticateComplete)
	return a
}

func (a *Api) RegisterBegin(writer http.ResponseWriter, request *http.Request) {
	a.registrationStateLock.Lock()
	defer a.registrationStateLock.Unlock()
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
		if time.Now().After(t.Add(RegisterTimeout)) {
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

		if err := a.db.Register(userId.String(), r); err != nil {
			http.Error(writer, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}

		name := U2fTokenId
		encoded, err := a.secureCookie.Encode(name, userId.String())
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		cookie := &http.Cookie{
			Name:     name,
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			Expires:  time.Now().Add(10 * time.Hour * 24 * 365 * 10),
		}
		http.SetCookie(writer, cookie)
		delete(a.registrationState, userId)
	} else {
		http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
}

func (a *Api) AuthenticateBegin(writer http.ResponseWriter, request *http.Request) {
	requestData, err := ioutil.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	authRequest := &AuthenticationRequest{}
	err = json.Unmarshal(requestData, &authRequest)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	var value string
	if cookie, err := request.Cookie(U2fTokenId); err == nil {
		if err = a.secureCookie.Decode(U2fTokenId, cookie.Value, &value); err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	keyIdentifier, err := a.db.GetKeyHandle(value)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	challenge, err := uuid.NewRandom()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	bChallenger, err := challenge.MarshalBinary()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	signRequestData := SignRequestData{
		KeyHandle: WebSafeB64Encode(keyIdentifier),
		AppId:     a.appId,
		Version:   U2fVersion,
		Challenge: WebSafeB64Encode(bChallenger),
	}
	response, _ := json.Marshal(signRequestData)
	_, _ = writer.Write(response)
}

func (a *Api) AuthenticateComplete(writer http.ResponseWriter, request *http.Request) {
	requestData, _ := ioutil.ReadAll(request.Body)
	if r, err := ParseSignatureResponse(requestData); err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else {
		var value string
		if cookie, err := request.Cookie(U2fTokenId); err == nil {
			if err = a.secureCookie.Decode(U2fTokenId, cookie.Value, &value); err != nil {
				http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		pubKey, err := a.db.GetPublicKey(value)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}

		AppIdIdna, err := idna.ToASCII(r.ClientData.Origin)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		hashBuf := sha256.Sum256(signBuffer)
		if ecdsa.Verify(pubKey, hashBuf[:], esig.R, esig.S) {
			http.Error(writer, http.StatusText(http.StatusOK), http.StatusOK)
			return
		} else {
			http.Error(writer, http.StatusText(http.StatusNotAcceptable), http.StatusNotAcceptable)
			return
		}
	}
}
