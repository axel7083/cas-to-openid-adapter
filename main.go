package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/axel7083/cas-to-openid-adapter/exampleop"
	"github.com/axel7083/cas-to-openid-adapter/storage"
	"io/ioutil"
	"log"
	"net/http"
)

func loadPrivateKey(file string) (*rsa.PrivateKey, error) {
	// Read the PEM private keys file
	pemData, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	// Decode the PEM data
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, err
	}

	// Parse the decoded data as an RSA private keys
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Assert that the parsed keys is an RSA private keys
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, err
	}

	return rsaPrivateKey, nil
}

func loadPublicKey(file string) (*rsa.PublicKey, error) {
	// Read the PEM public keys file
	pemData, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	// Decode the PEM data
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, err
	}

	// Parse the decoded data as an RSA public keys
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Assert that the parsed keys is an RSA public keys
	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, err
	}

	return publicKey, nil
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received %s request for %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func main() {

	opts := exampleop.Options{}
	err := exampleop.ParseOptionsFromEnv(&opts)
	if err != nil {
		log.Fatal("error parsing options from environment variables:", err)
	}

	privateKey, err := loadPrivateKey(opts.SigningPrivateKey)
	if err != nil {
		log.Fatal("error loading private keys from file:", err)
	}

	publicKey, err := loadPublicKey(opts.SigningPublicKey)
	if err != nil {
		log.Fatal("error loading public keys from file:", err)
	}

	oidcStorage := storage.NewStorage(storage.NewUserStore(), privateKey, opts.SigningKeyID, publicKey)

	log.Printf("creating server with prefix %s", opts.PrefixURL)
	router := exampleop.SetupServer(opts, oidcStorage)

	server := &http.Server{
		Addr:    opts.Host + ":" + opts.Port,
		Handler: loggingMiddleware(router),
	}
	log.Printf("server listening on http://%s:%s/", opts.Host, opts.Port)
	log.Println("press ctrl+c to stop")
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
