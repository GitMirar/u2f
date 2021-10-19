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

type AuthenticationRequest struct {
	UserId               string `json:"user_id"`
	AuthenticationSecret string `json:"authentication_secret"`
}

type AuthenticationCallback func(authStatus int, writer http.ResponseWriter, request *http.Request, userIdentifier string)
