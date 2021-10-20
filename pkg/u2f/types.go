package u2f

import "net/http"

type RegistrationData struct {
	Challenge string `json:"challenge"`
	AppId     string `json:"appId"`
	Version   string `json:"version"`
}

type RegistrationResponseRaw struct {
	RegistrationData string `json:"registrationData"`
	AppId            string `json:"appId"`
	ClientData       string `json:"clientData"`
}

type RegistrationResponse struct {
	ClientData    *RegistrationResponseClientData
	ClientDataRaw []byte
	PubKey        []byte
	KeyHandle     []byte
	Cert          []byte
	Signature     []byte
	AppId         string
}

type RegistrationResponseClientData struct {
	Typ         string `json:"typ"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

type SignRequestData struct {
	Version   string `json:"version"`
	KeyHandle string `json:"keyHandle"`
	AppId     string `json:"appId"`
	Challenge string `json:"challenge"`
}

type SignResponseDataRaw struct {
	ClientData    string `json:"clientData"`
	ErrorCode     int    `json:"errorCode"`
	KeyHandle     string `json:"keyHandle"`
	SignatureData string `json:"signatureData"`
}

type SignResponseClientData struct {
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
	Typ       string `json:"typ"`
}

type SignResponseSignatureData struct {
	UserPresence bool
	Counter      int
	Signature    []byte
}

type SignResponse struct {
	ErrorCode     int
	ClientDataRaw []byte
	ClientData    *SignResponseClientData
	SignatureData *SignResponseSignatureData
}

// AuthenticationCompletedCallback is called when the U2F authentication either has failed or succeeded.
// The writer object should be used to send an appropriate response to the frontend.
type AuthenticationCompletedCallback func(authStatus int, writer http.ResponseWriter, request *http.Request, keyIdentifier string)

// RegistrationCompletedCallback is called when a new key successfully enrolled.
// In case the enrollment request should be declined return false, otherwise return true.
type RegistrationCompletedCallback func(writer http.ResponseWriter, request *http.Request, keyIdentifier string) (ok bool)

// UserAuthenticationCallback is called to authenticate a user in the "authenticate begin" step.
// The function must return true for a successful authentication and the identifier that corresponds to the stored
// key slot for the U2F device.
// A typical scenario would be a lookup in a user database that contains
// UNIQUE(userId == keyslotId), UNIQUE(username), password
type UserAuthenticationCallback func(authData []byte, request *http.Request) (authenticationSuccess bool, identifier string)
