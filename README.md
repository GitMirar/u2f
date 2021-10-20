# U2F Server Implementation

This repository implements a register and authenticate endpoint and provides frontend (JavaScript) code that
demonstrates a simplified registration and authentication workflow.

The portion of U2F auth that is implemented here is reduced to the absolute minimum and does not include device
attestation or any other advanced features.

## Frontend

You can find a simple register and auth demo application
at [index.html](https://github.com/GitMirar/u2f/blob/master/html/index.html)
that
utilizes [u2f-api-1.1.js](https://github.com/Yubico/java-webauthn-server/blob/master/webauthn-server-demo/src/main/webapp/lib/u2f-api-1.1.js)
to interface with U2F keys.

## Backend

The following API endpoints are implemented:

* `/auth/register/begin` Initiate registration of a new U2F key, retrieve requested key handle from server.
* `/auth/register/complete` Complete the registration of a new U2F key by providing the backend with an ecdsa key that
  is signed with the device certificate (ecdsa) for the requested key handle.
* `/auth/authenticate/begin` Initiate user authentication via U2F, provide user credentials, retrieve challenge from
  server.
* `/auth/authenticate/complete` Complete the authentication by submitting the ecdsa signed challenge back to the server.

Use `u2f.NewU2FApi` with a `http.HTTPServer` to integrate the authentication endpoints into your web application. The
HTTP server must server content via HTTPS for U2F to work.

You must also provide a database that stores key handles and public keys associated with key identifiers.
See [db_interface.go](https://github.com/GitMirar/u2f/blob/master/pkg/u2f/db_interface.go).

For a complete demo server application have a look
at [u2f-demo-server](https://github.com/GitMirar/u2f/tree/master/cmd/u2f-demo-server).

### Cookies

The `/auth/authenticate/begin`  API sets a cookie named `U2FTID` that stores the key identifier for the duration of the
authentication process.

# Further Resources

You may want to read at least [FIDO-U2F-CHEAT-SHEET.pdf](https://neowave.fr/pdfs/FIDO-U2F-CHEAT-SHEET.pdf) before using
this code.

# License

This code may be used under the [BSD-3-Clause License](https://github.com/GitMirar/u2f/blob/master/LICENSE)
