package u2f

import (
	"fmt"
	"io/ioutil"
	oldlog "log"
	"net/http"
	"regexp"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

/*
HTTPServer is only part of this package for use in the U2F demo server.
Don't use this code directly for anything important.
*/
type HTTPServer struct {
	htmlDir      string
	port         uint16
	hostname     string
	bindAddress  string
	tlsCert      string
	tlsKey       string
	router       *mux.Router
	server       *http.Server
	contentType  map[string]string
	contentRegex map[*regexp.Regexp]string
}

// CORSMiddleware handle CORS and pre-flight requests
func (s *HTTPServer) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS for the lazy, just allow all
		// TODO: use hostname property and additional options for CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-Content-Type-Options, X-CSRF-Token, Authorization, auth")
		if (*r).Method == "OPTIONS" {
			// we got an OPTIONS request, just return 200
			w.WriteHeader(200)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HeaderMiddleware set some headers
func (s *HTTPServer) HeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		matched := false
		for re, h := range s.contentRegex {
			if re.MatchString(r.RequestURI) {
				w.Header().Set("Content-Type", h)
				matched = true
				break
			}
		}
		if !matched {
			// default to JSON, likely this is an API request
			w.Header().Set("Content-Type", "application/json")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *HTTPServer) Start() error {
	for regex, h := range s.contentType {
		if km, err := regexp.Compile(regex); err != nil {
			log.Warnf("ContentType regex %s did not compile due to %v", regex, err)
		} else {
			s.contentRegex[km] = h
		}
	}
	s.router.PathPrefix("/").Handler(http.FileServer(http.Dir(s.htmlDir)))
	if s.tlsCert != "" && s.tlsKey != "" {
		return s.server.ListenAndServeTLS(s.tlsCert, s.tlsKey)
	}
	return s.server.ListenAndServe()
}

func (s *HTTPServer) HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) *mux.Route {
	return s.router.HandleFunc(path, f)
}

func (s *HTTPServer) GetRouter() (router *mux.Router) {
	return s.router
}

func NewHTTPServer(bindAddress string, port uint16, hostname string, htmlDir string, tlsCert string, tlsKey string) *HTTPServer {
	s := &HTTPServer{
		router:       mux.NewRouter().StrictSlash(true),
		hostname:     hostname,
		bindAddress:  bindAddress,
		port:         port,
		htmlDir:      htmlDir,
		contentType:  map[string]string{},
		contentRegex: map[*regexp.Regexp]string{},
		tlsCert:      tlsCert,
		tlsKey:       tlsKey,
	}

	// specify content types
	s.contentType["^[/]{0,1}$"] = "text/html; charset=utf-8"
	s.contentType["(?i)^/.*[.](js|mjs)$"] = "application/javascript"
	s.contentType["(?i)^/.*[.](html)$"] = "text/html; charset=utf-8"

	s.router = mux.NewRouter().StrictSlash(true)
	s.router.Use(s.CORSMiddleware)
	s.router.Use(s.HeaderMiddleware)
	s.router.Use(handlers.CompressHandler)

	bindString := fmt.Sprintf("%s:%d", s.bindAddress, s.port)
	log.Infof("Starting HTTP server on %s", bindString)

	s.server = &http.Server{
		Addr:              bindString,
		Handler:           s.router,
		TLSConfig:         nil,
		ReadTimeout:       0,
		ReadHeaderTimeout: 0,
		WriteTimeout:      0,
		IdleTimeout:       0,
		MaxHeaderBytes:    0,
		TLSNextProto:      nil,
		ConnState:         nil,
		ErrorLog:          oldlog.New(ioutil.Discard, "", 0),
		BaseContext:       nil,
		ConnContext:       nil,
	}

	return s
}
