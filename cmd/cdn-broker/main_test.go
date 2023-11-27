package main_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/alphagov/paas-cdn-broker/config"
	. "github.com/alphagov/paas-cdn-broker/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TLS Configuration", func() {

	var testConfig *Settings
	var mockCDNBrokerServer *http.Server
	var tlsConfig *tls.Config

	const (
		mockPort     = 8443
		mockEndpoint = "/api/test"
	)

	BeforeEach(func() {
		createCredentials(testConfig)

		tlsConfig, err := testConfig.Tls.GenerateTLSConfig()
		Expect(err).NotTo(HaveOccurred())

		mockCDNBrokerServer = &http.Server{
			Addr:      fmt.Sprintf(":%d", mockPort),
			TLSConfig: tlsConfig,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Hello, CDN Broker!"))
			}),
		}

		go func() {
			Expect(mockCDNBrokerServer.ListenAndServeTLS(testConfig.Tls.Certificate, testConfig.Tls.PrivateKey)).To(Succeed())
		}()
	})

	AfterEach(func() {
		Expect(mockCDNBrokerServer.Close()).To(Succeed())
	})

	It("should use TLS", func() {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
		resp, err := client.Get(fmt.Sprintf("https://localhost:%d%s", mockPort, mockEndpoint))
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()

		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		body, err := io.ReadAll(resp.Body)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(body)).To(Equal("Hello, CDN Broker!"))
	})
})

func createCredentials(cdnBrokerConfig *config.Settings) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		IsCA:        true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	Expect(err).NotTo(HaveOccurred())

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	cdnBrokerConfig.Tls = &config.TLSConfig{
		Certificate: string(certPEM),
		PrivateKey:  string(keyPEM),
	}
}
