package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	//"github.com/davecgh/go-spew/spew"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

var key = flag.String("key", "server.key", "Server TLS key")
var crt = flag.String("cert", "server.crt", "Server TLS certificate")
var listen = flag.String("listen", ":https", "Server listen address")
var redirect = flag.String("redirect", "http://localhost:8080", "Reverse-proxied address")

type requestLog struct {
	req        *http.Request
	h          string
	respStatus int
}

func (rl *requestLog) String() string {
	return fmt.Sprintf("%s - %s - %s %s - %s - %d",
		time.Now(),
		rl.req.RemoteAddr,
		rl.req.Method,
		rl.req.RequestURI,
		rl.h,
		rl.respStatus,
	)
}

func main() {
	log.SetFlags(log.Lshortfile)
	flag.Parse()

	cer, err := tls.LoadX509KeyPair(*crt, *key)
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cer},
		ClientAuth:   tls.RequestClientCert,
		//ClientAuth:            tls.RequireAnyClientCert,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyPeerCertificate,
	}

	server := &http.Server{
		Addr:    *listen,
		Handler: http.HandlerFunc(handleHTTP),
		// Disable HTTP/2
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig:    config,
	}

	log.Fatal(server.ListenAndServeTLS("", ""))
}

func verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return nil //errors.New("no given certificate")
	}

	crt, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}

	errSig := crt.CheckSignatureFrom(crt)
	if errSig != nil {
		return errSig
	}

	return nil
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	rl := requestLog{req: req}
	defer func() {
		println(rl.String())
	}()

	redirectReq, err := http.NewRequest(req.Method, *redirect+req.RequestURI, req.Body)
	if err != nil {
		rl.respStatus = http.StatusServiceUnavailable
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	copyHeader(redirectReq.Header, req.Header)

	redirectReq.Header.Add("X-Forward-For", req.RemoteAddr)

	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		cert := req.TLS.PeerCertificates[0]
		h := sha256.Sum256(cert.Raw)
		hb64 := base64.URLEncoding.EncodeToString(h[:])
		redirectReq.Header.Add("X-Alias-ClientCert-SHA256", hb64)
		rl.h = hb64
	}

	// Create a client and query the target
	var transport http.Transport
	redirectResp, err := transport.RoundTrip(redirectReq)
	if err != nil {
		rl.respStatus = http.StatusServiceUnavailable
		http.Error(w, "", http.StatusServiceUnavailable)
		return
	}
	rl.respStatus = redirectResp.StatusCode

	defer redirectResp.Body.Close()
	copyHeader(w.Header(), redirectResp.Header)
	w.WriteHeader(redirectResp.StatusCode)
	io.Copy(w, redirectResp.Body)
}

func copyHeader(dest http.Header, source http.Header) {
	for n, v := range source {
		for _, vv := range v {
			dest.Add(n, vv)
		}
	}
}
