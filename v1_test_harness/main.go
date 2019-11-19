package main

import (
	"code.cloudfoundry.org/lager"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/lego/acme"
	"github.com/18F/cf-cdn-service-broker/models"
	"io/ioutil"
	"os"
	"time"

	"github.com/18F/cf-cdn-service-broker/utils"
)

func main() {
	logger := lager.NewLogger("v1-test-harness")
	logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.INFO))

	timer := time.NewTimer(30 * time.Second)

	keyArg := os.Args[1]
	emailArg := os.Args[2]
	uriArg := os.Args[3]
	keyContent, err := ioutil.ReadFile(keyArg)
	domains := []string{"le-test-3.severalbadgers.com"}

	if err != nil {
		logger.Fatal("read-key", err)
	}

	key, err := x509.ParsePKCS1PrivateKey(keyContent)
	if err != nil {
		logger.Fatal("parse-key", err)
	}

	usr := utils.User{
		Email: emailArg,
		Registration: &acme.RegistrationResource{
			Body:        acme.Registration{},
			URI:         uriArg,
			NewAuthzURL: "https://acme-v01.api.letsencrypt.org/acme/new-authz",
			TosURL:      "",
		},
		OrderURL: "",
	}
	usr.SetPrivateKey(*key)

	settings := config.Settings{
		Email:   emailArg,
		AcmeUrl: "https://acme-v01.api.letsencrypt.org/directory",
	}

	client, err := acme.NewClient(settings.AcmeUrl, &usr, acme.RSA2048)
	if err != nil {
		logger.Fatal("new-client", err)
	}

	err = client.SetChallengeProvider(acme.DNS01, &models.DNSProvider{})
	if err != nil {
		logger.Fatal("set-challenge-provider", err)
	}

	client.ExcludeChallenges([]acme.Challenge{acme.TLSSNI01, acme.HTTP01})
	if err != nil {
		logger.Fatal("create-client", err)
	}

	//certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	//if err != nil {
	//	logger.Fatal("generate-cert-key", err)
	//}

	challenges, errs := client.GetChallenges(domains)
	if len(errs) > 0 {
		for key, e := range errs {
			logger.Error("get-challenges", e, lager.Data{"key": key})
		}
		logger.Fatal("get-challenges", errors.New("failed to get challenges"))
	}

	var instructions []string
	for _, auth := range challenges {
		for _, challenge := range auth.Body.Challenges {
			if challenge.Type == acme.DNS01 {
				logger.Info(
					"get-key-authorization-for-a-dns-challenge",
					lager.Data{
						"domain": auth.Domain,
					},
				)
				keyAuth, err := acme.GetKeyAuthorization(
					challenge.Token,
					usr.GetPrivateKey(),
				)
				if err != nil {
					logger.Fatal("get-key-authorization-err", err)
				}
				fqdn, value, ttl := acme.DNS01Record(auth.Domain, keyAuth)
				instructions = append(instructions, fmt.Sprintf(
					"name: %s, value: %s, ttl: %d",
					fqdn, value, ttl,
				))
			}
		}
	}

	logger.Info("DNS", lager.Data{"records": instructions})

	for {
		select {
		case <-timer.C:
			logger.Info("try-solve-challenges", lager.Data{"challenges": challenges})
			failures := client.SolveChallenges(challenges)

			if len(failures) > 0 {
				logger.Error("solve-challenges-errors", fmt.Errorf(
					"Encountered non-zero number of failures solving challenges",
				), lager.Data{
					"failures": failures,
				})

				timer.Reset(30 * time.Second)
				continue
			}

			logger.Info("solve-challenges-success", lager.Data{})

			certs, err := client.RequestCertificate(challenges, true, nil, false)
			if err != nil {
				logger.Error("request-certificate", err)
				timer.Reset(30 * time.Second)
				continue
			}certs.

			fmt.Print(string(certs.Certificate))
			logger.Info("certificate-obtained")
			break
		}
	}
}
