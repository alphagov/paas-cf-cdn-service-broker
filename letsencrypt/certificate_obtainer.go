package letsencrypt

import (
	"code.cloudfoundry.org/lager"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
)

const ErrorOrderExpired = "order has expired"
const ChallengeTypeDNS = "dns-01"
const ChallengeTypeHTTP = "http-01"
const ChallengeTypeTLS = "tls-alpn-01"

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -o fakes/FakeCertificateObtainer.go --fake-name FakeCertificateObtainer . CertificateObtainerInterface
type CertificateObtainerInterface interface {
	BeginCertificateOrder(ctx context.Context, client ClientInterface, domains []string) (*acme.Order, error)
	SolveAuthorizations(ctx context.Context, client ClientInterface, orderURL string) (*x509.Certificate, *rsa.PrivateKey, bool, error)
}

type DNSCertificateObtainer struct {
	Logger          lager.Logger
	ChallengeSolver ChallengeSolverInterface
}

func NewDNSCertificateObtainer(logger lager.Logger) CertificateObtainerInterface {
	return DNSCertificateObtainer{
		Logger:          logger,
		ChallengeSolver: NewDNS01ChallengeSolver(logger),
	}
}

func (d DNSCertificateObtainer) BeginCertificateOrder(ctx context.Context, client ClientInterface, domains []string) (*acme.Order, error) {
	logSess := d.Logger.Session("begin-certificate-order", lager.Data{"domains": domains})

	ids := acme.DomainIDs(domains...)
	orderOpts := []acme.OrderOption{}

	logSess.Info("authorize-order")
	order, err := client.AuthorizeOrder(ctx, ids, orderOpts...)

	if err != nil {
		logSess.Error("authorize-order-error", err)
		return nil, err
	}
	logSess.Info("authorize-order-success")

	records := map[string]string{}
	for _, authURL := range order.AuthzURLs {
		auth, _ := client.GetAuthorization(ctx, authURL)

		domain := fmt.Sprintf("_acme-challenge.%s", auth.Identifier.Value)

		for _, challenge := range auth.Challenges {
			if challenge.Type == ChallengeTypeDNS {
				value, _ := client.DNS01ChallengeRecord(challenge.Token)
				records[domain] = value
			}
		}
	}

	logSess.Info("required-dns-records", lager.Data{"records": records})

	return order, nil
}

func (d DNSCertificateObtainer) SolveAuthorizations(ctx context.Context, client ClientInterface, orderURL string) (*x509.Certificate, *rsa.PrivateKey, bool, error) {
	logSess := d.Logger.Session("solve-authorizations")

	logSess.Info("get-order")
	order, err := client.GetOrder(ctx, orderURL)

	if err != nil {
		logSess.Error("get-order-error", err)
		return nil, nil, false, err
	}
	logSess.Info("get-order-success", lager.Data{"order": order})

	domains := make([]string, len(order.Identifiers))
	for _, value := range order.Identifiers {
		domains = append(domains, value.Value)
	}
	logSess.WithData(lager.Data{"domains": domains})

	if order.Status == acme.StatusPending {
		logSess.Info("order-pending", LogDataOrderPending)

		satisfied, unsatisfied, err := attemptToSatisfyAuthorizations(ctx, client, d.ChallengeSolver, order, logSess)
		if err != nil {
			logSess.Error("try-satisfy-authorizations-error", err)
			return nil, nil, false, nil
		}
		logSess.Info(
			"try-satisfy-authorizations-complete",
			lager.Data{
				"satisfied_authorizations":   satisfied,
				"unsatisfied_authorizations": unsatisfied,
			},
		)

		return nil, nil, false, nil
	}

	if order.Status == acme.StatusExpired {
		logSess.Info(
			"order-expired",
			lager.Data{
				"expiry_time": order.Expires,
				"message":     "certificate order has expired. The tenant will need to update the service once we've gotten it in to a state where they can.",
			},
		)
		return nil, nil, false, fmt.Errorf(ErrorOrderExpired)
	}

	if order.Status != acme.StatusReady {
		auths := []acme.Authorization{}
		for _, authURL := range order.AuthzURLs {
			auth, err := client.GetAuthorization(ctx, authURL)

			if err != nil {
				return nil, nil, false, fmt.Errorf("failed to get authorization")
			}

			auths = append(auths, *auth)
		}
		logSess.Info("wrong-status", lager.Data{"status": order.Status, "message": "order status must be 'ready'", "auths": auths})
		return nil, nil, false, fmt.Errorf("order status is '%s'", order.Status)
	}

	logSess.Info("generate-cert-private-key")
	certPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logSess.Error("generate-cert-private-key-error", err)
		return nil, nil, true, err
	}

	logSess.Info("create-csr", lager.Data{"subject": domains[0], "dns_names": domains[1:]})
	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: domains[0],
			},
			DNSNames: domains[1:],
		},
		certPrivateKey,
	)

	if err != nil {
		return nil, nil, true, errors.Wrap(err, "failed to create csr")
	}

	logSess.Info("create-order-cert", lager.Data{"cert_url": order.FinalizeURL})
	cert, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, false)

	if err != nil {
		return nil, nil, true, errors.Wrap(err, "failed to create cert")
	}
	logSess.Info("create-order-cert-success")

	logSess.Info("parse-certificate")
	x509Cert, err := x509.ParseCertificate(cert[0])
	if err != nil {
		logSess.Error("parse-certificate-error", err)
		return nil, nil, false, err
	}

	return x509Cert, nil, true, nil
}

// Attempts to satisfy each authorization on an order in turn,
// returning the satisfied and unsatisfied authorizations separately.
//
// Tenants are in control of setting the required DNS records, so
// in this method the attempt to satisfy an authorization is a
// call to Lets Encrypt to trigger it to check each challenge in turn.
func attemptToSatisfyAuthorizations(
	ctx context.Context,
	client ClientInterface,
	challengeSolver ChallengeSolverInterface,
	order *acme.Order,
	logger lager.Logger,
) (*[]acme.Authorization, *[]acme.Authorization, error) {
	logSess := logger.Session("try-satisfy")

	satisfiedAuths := []acme.Authorization{}
	unsatisfiedAuths := []acme.Authorization{}

	for _, authURL := range order.AuthzURLs {
		authLogSess := logSess.Session("try-satisfy-authorization")
		authLogSess.Info("get-authorization", lager.Data{"auth_url": authURL})

		auth, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			authLogSess.Error("get-authorization-error", err)
			return nil, nil, err
		}
		authLogSess.WithData(lager.Data{"status": auth.Status, "is_wildcard": auth.Wildcard, "expires_at": auth.Expires})

		if auth.Status == acme.StatusValid {
			satisfiedAuths = append(satisfiedAuths, *auth)
			continue
		} else {
			unsatisfiedAuths = append(unsatisfiedAuths, *auth)
		}

		switch auth.Status {
		case acme.StatusRevoked, acme.StatusDeactivated, acme.StatusExpired, acme.StatusInvalid:
			authLogSess.Info("invalid-status", LogDataAuthorizationInvalidStatus)
			continue

		case acme.StatusValid:
			authLogSess.Info("valid-authorization", LogDataAuthorizationValid)
			continue

		case acme.StatusPending:
			fallthrough
		default:
			authLogSess.Info("pending-authorization", LogDataAuthorizationPending)
		}

		for _, challenge := range auth.Challenges {
			authLogSess.Info("challenge", lager.Data{"status": challenge.Status, "challenge": challenge.Token, "type": challenge.Type})

			if !challengeSolver.Accept(challenge) {
				authLogSess.Info("skip", lager.Data{"message": "challenge solver does not accept challenges of this type", "type": challenge.Type})
				continue
			}

			if challenge.Status == acme.StatusValid || challenge.Status == acme.StatusInvalid {
				continue
			}

			logSess.Info("validate-challenge")
			ok, err := challengeSolver.TrySolveChallenge(auth, challenge, client)

			if err != nil {
				authLogSess.Error("validate-challenge-error", err)
				continue
			}
			authLogSess.Info("validate-challenge-success")

			if !ok {
				authLogSess.Info("challenge-not-ready")
				continue
			}

			authLogSess.Info("try-accept-challenge")
			ch, err := client.Accept(ctx, challenge)
			if err != nil {
				return nil, nil, errors.Wrap(err, "failed to accept challenge in an unexpected way")
			}

			if ch.Error != nil {
				authLogSess.Info("try-accept-challenge-error", lager.Data{"error": ch.Error})
			} else {
				authLogSess.Info("challenge-accepted", lager.Data{"status": ch.Status, "challenge": ch.Token, "type": ch.Type})

				if ch.Status == acme.StatusValid {
					authLogSess.Info("challenge-valid", lager.Data{"message": "found a challenge which is valid. Not trying any others."})
					return &satisfiedAuths, &unsatisfiedAuths, nil
				}
			}

		}
	}

	return &satisfiedAuths, &unsatisfiedAuths, nil
}

var LogDataAuthorizationPending = lager.Data{"message": "the authorization is pending and needs its challenges solving"}
var LogDataAuthorizationValid = lager.Data{"message": "the authorization is in the valid state and does not need its challenges solving"}
var LogDataAuthorizationInvalidStatus = lager.Data{
	"message": "the authorization is not in a state where challenges can be solved",
	"help":    "https://tools.ietf.org/html/rfc8555#section-7.1.6",
}
var LogDataOrderPending = lager.Data{
	"status":  acme.StatusPending,
	"message": "status is 'pending', indicating that one or more authorizations are not yet complete",
	"help":    "https://tools.ietf.org/html/rfc8555#section-7.1.6",
}
