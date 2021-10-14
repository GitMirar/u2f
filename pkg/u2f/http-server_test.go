package u2f

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
)

func WebHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("OK"))
}

func TestHTTPServer(t *testing.T) {
	server := NewHTTPServer("0.0.0.0", 8000, "localhost", "./html", "", "")
	if server == nil {
		t.Fatal("could not start server")
	}

	server.HandleFunc("/test", WebHandler)

	go func() {
		if err := server.Start(); err != nil {
			t.Errorf("could not start the server due to %v", err)
		}
	}()

	_, err := http.Get("http://localhost:8000")
	if err != nil {
		t.Errorf("GET / failed due to %v", err)
	}

	_, err = http.Get("http://localhost:8000/index.html")
	if err != nil {
		t.Errorf("GET /index.html failed due to %v", err)
	}

	response, err := http.Get("http://localhost:8000/test")
	if err != nil {
		t.Errorf("GET /test failed due to %v", err)
	}
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Errorf("could not read the response Body due to %v", err)
	}
	if string(responseData) != "OK" {
		t.Errorf("unexpected response %v", responseData)
	}
}

func TestHTTPSServer(t *testing.T) {
	certfile := "httptest.crt"
	keyfile := "httptest.pem"

	if err := GenerateCertificate("localhost,127.0.0.1", "TestOrg", certfile, keyfile); err != nil {
		t.Fatalf("failed to generate a TLS certificate due to %v", err)
	}

	server := NewHTTPServer("0.0.0.0", 8443, "localhost", "./html", certfile, keyfile)
	if server == nil {
		t.Fatal("could not start server")
	}

	server.HandleFunc("/test", WebHandler)

	go func() {
		if err := server.Start(); err != nil {
			t.Errorf("could not start the server due to %v", err)
		}
	}()

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	_, err := http.Get("https://localhost:8443")
	if err != nil {
		t.Errorf("GET / failed due to %v", err)
	}

	response, err := http.Get("https://localhost:8443/test")
	if err != nil {
		t.Errorf("GET /test failed due to %v", err)
	}
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Errorf("could not read the response Body due to %v", err)
	}
	if string(responseData) != "OK" {
		t.Errorf("unexpected response %v", responseData)
	}

	_ = os.Remove(certfile)
	_ = os.Remove(keyfile)
}
