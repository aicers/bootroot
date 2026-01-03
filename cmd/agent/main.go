package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// MyUser implements lego.User interface
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u *MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type EABKey struct {
	KID string `json:"kid"`
	Key string `json:"key"`
}

func main() {
	server := flag.String("server", "https://localhost:9000/acme/acme/directory", "ACME Directory URL")
	email := flag.String("email", "admin@example.com", "User Email")
	domains := flag.String("domains", "localhost", "Comma separated domains")
	outDir := flag.String("out", "./certs", "Output directory for certificates")
	rootFile := flag.String("root", "", "Path to Root CA file (PEM)")

	eabKid := flag.String("eab-kid", "", "Key ID for External Account Binding")
	eabHmac := flag.String("eab-hmac", "", "HMAC Key for External Account Binding")
	eabFile := flag.String("eab-file", "", "Path to JSON file containing EAB credentials")

	flag.Parse()

	if *domains == "" {
		log.Fatal("At least one domain is required")
	}

	// Resolve EAB credentials
	kid := *eabKid
	hmac := *eabHmac

	if *eabFile != "" {
		data, err := os.ReadFile(*eabFile)
		if err != nil {
			log.Fatalf("Failed to read EAB file: %v", err)
		}
		var eab EABKey
		if err := json.Unmarshal(data, &eab); err != nil {
			log.Fatalf("Failed to parse EAB file: %v", err)
		}
		if kid == "" {
			kid = eab.KID
		}
		if hmac == "" {
			hmac = eab.Key
		}
	}

	// 1. Create User and Private Key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: *email,
		key:   privateKey,
	}

	// 2. Client Config
	config := lego.NewConfig(&myUser)
	config.CADirURL = *server
	config.Certificate.KeyType = certcrypto.EC256

	// Configure Custom HTTP Client if Root CA is provided
	if *rootFile != "" {
		caCert, err := os.ReadFile(*rootFile)
		if err != nil {
			log.Fatal("Error reading Root CA file:", err)
		}

		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			log.Fatal("Failed to append Root CA to pool")
		}

		// Create Transport with Trusted CA
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			},
		}

		// Lego uses HTTPClient for ACME requests
		config.HTTPClient = &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
		}
	}

	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Register Account (with EAB if provided)
	regOptions := registration.RegisterOptions{TermsOfServiceAgreed: true}
	var reg *registration.Resource

	if kid != "" && hmac != "" {
		// Use RegisterWithExternalAccountBinding when EAB credentials are provided
		eabOptions := registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  kid,
			HmacEncoded:          hmac,
		}
		reg, err = client.Registration.RegisterWithExternalAccountBinding(eabOptions)
	} else {
		reg, err = client.Registration.Register(regOptions)
	}

	if err != nil {
		log.Fatal("Registration failed:", err)
	}
	myUser.Registration = reg

	// 4. Setup Challenge Solver
	// Use HTTP01 Provider server on port 5002 (requires port forwarding or open network)
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
	if err != nil {
		log.Fatal(err)
	}

	// 5. Obtain Certificate
	request := certificate.ObtainRequest{
		Domains: strings.Split(*domains, ","),
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal("Obtain failed:", err)
	}

	// 6. Save to file
	if err := os.MkdirAll(*outDir, 0700); err != nil {
		log.Fatal(err)
	}

	certPath := filepath.Join(*outDir, "server.crt")
	keyPath := filepath.Join(*outDir, "server.key")

	err = os.WriteFile(certPath, certificates.Certificate, 0600)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(keyPath, certificates.PrivateKey, 0600)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Successfully issued certificate for %s\n", *domains)
	fmt.Printf("Cert: %s\nKey: %s\n", certPath, keyPath)
}
