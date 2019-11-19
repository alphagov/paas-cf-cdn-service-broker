package main

import (
	"code.cloudfoundry.org/lager"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/18F/cf-cdn-service-broker/letsencrypt"
	"github.com/18F/cf-cdn-service-broker/utils"
	"golang.org/x/crypto/acme"
	"os"
	"time"
)

func main() {
	logger := lager.NewLogger("test-harness")
	logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.INFO))
	ctx := context.Background()
	domain := os.Args[1]
	timer := time.NewTimer(30 * time.Second)

	user := utils.User{
		Email:        "andy.hunt+2@digital.cabinet-office.gov.uk",
		Registration: nil,
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Fatal("generate-key", err)
	}
	user.SetPrivateKey(*key)

	accounter := letsencrypt.NewAccountCreator(logger)
	_, client, err := accounter.EnsureAccount(ctx, user)
	if err != nil {
		logger.Fatal("ensure-account", err)
	}

	obtainer := letsencrypt.NewDNSCertificateObtainer(logger)
	order, err := obtainer.BeginCertificateOrder(ctx, client, []string{domain})

	if err != nil {
		logger.Fatal("begin-certificate-order", err)
	}

	for {
		select {
		case <-timer.C:
			cert, pk, triedChallenges, err := trySolveAuthorizations(obtainer, ctx, client, order)
			if triedChallenges == true && err == nil {
				fmt.Printf("%v", cert)
				fmt.Printf("%v", pk)
				break
			} else if err != nil {
				logger.Error("try-solve-auths", err)
				break
			} else {
				timer.Reset(30 * time.Second)
			}
		}
	}
}

func trySolveAuthorizations(obtainer letsencrypt.CertificateObtainerInterface, ctx context.Context, client letsencrypt.ClientInterface, order *acme.Order) (*x509.Certificate, *rsa.PrivateKey, bool, error) {
	return obtainer.SolveAuthorizations(ctx, client, order.URI)
}
