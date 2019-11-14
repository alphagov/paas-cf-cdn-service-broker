package letsencrypt

import (
	"code.cloudfoundry.org/lager"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
)

type DNSCertificateObtainer struct {
	logger lager.Logger
}

func NewDNSCertificateObtainer(logger lager.Logger) CertificateObtainer {
	return DNSCertificateObtainer{logger: logger}
}

func (d DNSCertificateObtainer) BeginCertificateOrder(ctx context.Context, client ClientInterface, domains []string) (*acme.Order, error) {
	logSess := d.logger.Session("begin-certificate-order", lager.Data{"domains": domains})

	ids := []acme.AuthzID{}
	for _, d := range domains {
		ids = append(ids, acme.AuthzID{Type: "dns", Value: d})
	}
	orderOpts := []acme.OrderOption{}

	logSess.Info("authorize-order")
	order, err := client.AuthorizeOrder(ctx, ids, orderOpts...)

	if err != nil {
		logSess.Error("authorize-order-error", err)
		return nil, err
	}
	logSess.Info("authorize-order-success")

	return order, nil
}

func (d DNSCertificateObtainer) SolveAuthorizations(ctx context.Context, client ClientInterface, orderURL string) (*[]byte, bool, error) {
	logSess := d.logger.Session("solve-authorizations", lager.Data{"orderURL": orderURL})

	logSess.Info("get-order")
	order, err := client.GetOrder(ctx, orderURL)

	if err != nil {
		logSess.Error("get-order-error", err)
		return nil, false, err
	}
	logSess.Info("get-order-success", lager.Data{"order": order})

	domains := make([]string, len(order.Identifiers))
	for _, value := range order.Identifiers {
		domains = append(domains, value.Value)
	}

	if order.Status == acme.StatusPending {
		logSess.Info(
			"waiting-for-authorizations",
			lager.Data{
				"status":         order.Status,
				"message":        "status is 'pending', indicating that one or more authorizations are not yet complete",
				"help":           "https://tools.ietf.org/html/rfc8555#section-7.1.6",
			},
		)

		logSess.Info("try-satisfy-authorizations")
		satisfied, unsatisfied, err := attemptToSatisfyAuthorizations(ctx, client, order, logSess)
		if err != nil {
			logSess.Error("try-satisfy-authorizations-error", err)
			return nil, false, nil
		}
		logSess.Info(
			"try-satisfy-authorizations-complete",
			lager.Data{
				"satisfied_authorizations": satisfied,
				"unsatisfied_authorizations": unsatisfied,
			},
		)


		return nil, false, nil
	}

	if order.Status == acme.StatusExpired {
		logSess.Info(
			"order-expired",
			lager.Data{
				"expiry_time": order.Expires,
				"message":     "certificate order has expired. The tenant will need to update the service once we've gotten it in to a state where they can.",
			},
		)
		return nil, false, fmt.Errorf(ErrorOrderExpired)
	}

	if order.Status != acme.StatusReady {
		logSess.Info("wrong-status", lager.Data{"status": order.Status, "message": "order status must be 'ready'"})
		return nil, false, fmt.Errorf("order status is '%s'", order.Status)
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
		client.GetKey(),
	)

	if err != nil {
		return nil, true, errors.Wrap(err, "failed to create csr")
	}

	logSess.Info("create-order-cert", lager.Data{"cert_url": order.CertURL})
	cert, _, err := client.CreateOrderCert(ctx, order.CertURL, csr, false)

	if err != nil {
		return nil, true, errors.Wrap(err, "failed to create cert")
	}
	logSess.Info("create-order-cert-success")

	return &cert[0], true, nil
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
	order *acme.Order,
	logger lager.Logger,
) (satisfied *[]acme.Authorization, unsatisfied *[]acme.Authorization, err error){
	logSess := logger.Session("satisfy-authorizations")

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
		authLogSess.Info("authorization-status", lager.Data{"status": auth.Status})
		authLogSess.WithData(lager.Data{"status": auth.Status, "is_wildcard": auth.Wildcard, "expires_at": auth.Expires})

		if auth.Status == acme.StatusValid {
			satisfiedAuths = append(satisfiedAuths, *auth)
			continue
		} else {
			unsatisfiedAuths = append(unsatisfiedAuths, *auth)
		}

		for _, challenge := range auth.Challenges {
			authLogSess.Info("challenge-status", lager.Data{"status": challenge.Status, "challenge": challenge.Token})
			if challenge.Status == acme.StatusValid {
				continue
			}

			if challenge.Status == acme.StatusInvalid {
				continue
			}

			authLogSess.Info("try-satisfy-challenge")
			ch, err := client.Accept(ctx, challenge)
			if err != nil {
				return nil, nil, errors.Wrap(err, "failed to accept challenge in an unexpected way")
			}

			if ch.Error != nil {
				authLogSess.Info("try-satisfy-challenge-error", lager.Data{"error": ch.Error})
			}

			authLogSess.Info("try-satisfy-challenge-success", lager.Data{"challenge": challenge.Token, "status": ch.Status})
		}
	}

	return &satisfiedAuths, &unsatisfiedAuths, nil
}
