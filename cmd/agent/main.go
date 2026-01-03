package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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

func main() {
	server := flag.String("server", "https://localhost:9000/acme/acme/directory", "ACME Directory URL")
	email := flag.String("email", "admin@example.com", "User Email")
	domains := flag.String("domains", "localhost", "Comma separated domains")
	outDir := flag.String("out", "./certs", "Output directory for certificates")
	rootFile := flag.String("root", "", "Path to Root CA file (PEM)")
	flag.Parse()

	if *domains == "" {
		log.Fatal("At least one domain is required")
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
				RootCAs: caCertPool,
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

	// 3. Register Account
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
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
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatal(err)
	}

	certPath := filepath.Join(*outDir, "server.crt")
	keyPath := filepath.Join(*outDir, "server.key")

	err = os.WriteFile(certPath, certificates.Certificate, 0644)
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
