package u2f

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
)

func ParseRegistrationResponse(response []byte) (registrationResponse *RegistrationResponse, err error) {
	registrationResponse = &RegistrationResponse{}

	registrationResponseRaw := &RegistrationResponseRaw{}
	if err = json.Unmarshal(response, &registrationResponseRaw); err != nil {
		return nil, err
	}

	registrationResponse.AppId = registrationResponseRaw.AppId

	registrationResponseClientDataBin, err := WebSafeB64Decode(registrationResponseRaw.ClientData)
	if err != nil {
		return nil, err
	}
	registrationResponseClientData := &RegistrationResponseClientData{}
	registrationResponse.ClientDataRaw = registrationResponseClientDataBin
	if err = json.Unmarshal(registrationResponseClientDataBin, &registrationResponseClientData); err != nil {
		return nil, err
	}
	registrationResponse.ClientData = registrationResponseClientData

	registrationResponseRegistrationDataBin, err := WebSafeB64Decode(registrationResponseRaw.RegistrationData)
	if err != nil {
		return nil, err
	}
	registrationResponse.PubKey = registrationResponseRegistrationDataBin[1 : 1+65]
	keyUserHandleLength := int(registrationResponseRegistrationDataBin[66])
	registrationResponse.KeyHandle = registrationResponseRegistrationDataBin[67 : 67+keyUserHandleLength]

	var certificateData, signatureData asn1.RawValue
	remainder, err := asn1.Unmarshal(registrationResponseRegistrationDataBin[67+keyUserHandleLength:], &certificateData)
	if err != nil {
		return nil, err
	}
	registrationResponse.Cert = certificateData.FullBytes

	_, err = asn1.Unmarshal(remainder, &signatureData)
	if err != nil {
		return nil, err
	}
	registrationResponse.Signature = signatureData.FullBytes

	return registrationResponse, err
}

func ParseSignatureResponse(response []byte) (signResponse *SignResponse, err error) {
	signResponse = &SignResponse{}

	raw := &SignResponseDataRaw{}
	if err := json.Unmarshal(response, raw); err != nil {
		return nil, err
	}
	signResponse.ErrorCode = raw.ErrorCode

	if decoded, err := WebSafeB64Decode(raw.ClientData); err != nil {
		return nil, err
	} else {
		signResponse.ClientData = &SignResponseClientData{}
		if err := json.Unmarshal(decoded, signResponse.ClientData); err != nil {
			return nil, err
		}
		signResponse.ClientDataRaw = decoded
	}
	signatureDataBin, err := WebSafeB64Decode(raw.SignatureData)
	if err != nil {
		return nil, err
	}

	signResponse.SignatureData = &SignResponseSignatureData{
		UserPresence: signatureDataBin[0] != 0,
		Counter:      int(binary.BigEndian.Uint32(signatureDataBin[1:5])),
		Signature:    signatureDataBin[5:],
	}

	return signResponse, nil
}

func WebSafeB64Encode(data []byte) (b64 string) {
	return strings.Replace(base64.URLEncoding.EncodeToString(data), "=", "", -1)
}

func WebSafeB64Decode(b64 string) (data []byte, err error) {
	padding := 0
	if len(b64)%4 != 0 {
		padding = 4 - (len(b64) % 4)
	}
	b64padded := b64 + strings.Repeat("=", padding)
	return base64.URLEncoding.DecodeString(b64padded)
}
