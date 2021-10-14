# U2F Flow

## Register

### Begin Register

`GET /api/register/begin`

#### Response

* Challenge : websafe b64
* AppId : not used
* Version: not used

The returned challenge is a 128bit identifier (uuid4 with 122bit randomness) that is used to identify this specific registration later on.

### End Register

`POST /api/register/complete`

#### Request

* RegistrationData
  * PublicKey : byte[]
  * KeyHandle : string
  * Certificate : der encoded certificate
  * Signature : byte[]
* AppId : not used
* ClientData : b64 encoded json
  * Typ : not used
  * Challenge : websafe b64
  * Origin : not used
  * CrossOrigin : not used

The challenge is used to tie the registration completion data to the registration request.

## Authenticate

### Begin Authenticate

`POST /api/authenticate/begin`

### Complete Authenticate

`POST /api/authenticate/complete`