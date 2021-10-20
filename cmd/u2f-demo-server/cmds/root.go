package cmds

import (
	"crypto/rand"
	"fmt"
	"github.com/gorilla/securecookie"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/GitMirar/u2f/pkg/u2f"
)

const (
	KeyFile      = "u2f-server-key.pem"
	CertFile     = "u2f-server.crt"
	MyU2fTokenId = "MyUID"
)

var secureCookie *securecookie.SecureCookie

func AuthCompletedCallback(authStatus int, writer http.ResponseWriter, _ *http.Request, keyIdentifier string) {
	switch authStatus {
	case u2f.U2F_STATUS_SUCCESS:
		log.Infof("Authentication successful for id %v", keyIdentifier)
		name := "SID"
		cookie := &http.Cookie{
			Name:     name,
			Value:    "some data authenticating a user session",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			Expires:  time.Now().Add(10 * time.Hour * 24 * 365 * 10),
		}
		http.SetCookie(writer, cookie)
		http.Error(writer, http.StatusText(http.StatusOK), http.StatusOK)
		break
	case u2f.U2F_STATUS_ERROR:
		log.Infof("Authentication error for id %v", keyIdentifier)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		break
	case u2f.U2F_STATUS_FAILURE:
		log.Infof("Authentication failed for id %v", keyIdentifier)
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		break
	}
}

func AuthCallback(authData []byte, request *http.Request) (authSuccessful bool, keyIdentifier string) {
	/*
		In a real application this callback would deal with authenticating the user and retrieving the matching keyIdentifier
		for this user.
	*/
	log.Infof("Authentication data %v", string(authData))
	if cookie, err := request.Cookie(MyU2fTokenId); err == nil {
		if err = secureCookie.Decode(MyU2fTokenId, cookie.Value, &keyIdentifier); err == nil {
			return true, keyIdentifier
		} else {
			return false, ""
		}
	}
	return false, ""
}

func RegistrationCompletedCallback(writer http.ResponseWriter, _ *http.Request, keyIdentifier string) (ok bool) {
	encoded, err := secureCookie.Encode(MyU2fTokenId, keyIdentifier)
	if err != nil {
		return false
	}
	cookie := &http.Cookie{
		Name:     MyU2fTokenId,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Now().Add(10 * time.Hour * 24 * 365 * 10),
	}
	http.SetCookie(writer, cookie)
	return true
}

var rootCmd = &cobra.Command{
	Use:   "u2f-server",
	Short: "U2F Demo Server",
	Long:  `Starts a U2F demo server.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Infof("Starting U2F demo server")

		domain, err := cmd.Flags().GetString("domain")
		if err != nil {
			panic(err)
		}
		bindAddress, err := cmd.Flags().GetString("bind-address")
		if err != nil {
			panic(err)
		}
		port, err := cmd.Flags().GetUint16("port")
		if err != nil {
			panic(err)
		}

		err = u2f.GenerateCertificate(domain, "U2F Demo Server", CertFile, KeyFile)
		if err != nil {
			log.Fatalf("failed to generate a selfsigned certificate due to %v", err)
			return
		}

		server := u2f.NewHTTPServer(bindAddress, port, domain, "./html", CertFile, KeyFile)
		if server == nil {
			log.Fatal("could not start server")
		}

		var hashKey, blockKey [32]byte
		if _, err := rand.Read(hashKey[:]); err != nil {
			log.Fatalf("error %v", err)
		}
		if _, err := rand.Read(blockKey[:]); err != nil {
			log.Fatalf("error %v", err)
		}
		u2f.NewU2FApi(server,
			u2f.NewMemDB(),
			fmt.Sprintf("https://%s:%d", domain, port),
			true,
			hashKey,
			blockKey,
			AuthCallback,
			AuthCompletedCallback,
			RegistrationCompletedCallback)

		if err := server.Start(); err != nil {
			log.Errorf("could not start the server due to %v", err)
		}

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	log.SetOutput(os.Stdout)
	rootCmd.Flags().StringP("domain", "d", "localhost", "The domain where the server is hosted")
	rootCmd.Flags().StringP("bind-address", "i", "0.0.0.0", "Bind address of the server")
	rootCmd.Flags().Uint16P("port", "p", 8443, "Port port where the server is hosted")

	var hashKey, blockKey [32]byte
	if _, err := rand.Read(hashKey[:]); err != nil {
		log.Fatalf("error %v", err)
	}
	if _, err := rand.Read(blockKey[:]); err != nil {
		log.Fatalf("error %v", err)
	}
	secureCookie = securecookie.New(hashKey[:], blockKey[:])
}
