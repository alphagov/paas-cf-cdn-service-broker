package letsencrypt

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
)

type CertificateObtainer interface {
	BeginCertificateOrder(ctx context.Context, client acme.Client, domains []string) (*acme.Order, error)
	SolveAuthorizations(ctx context.Context, client acme.Client, orderURL string) (*[]byte, bool, error)
}

type DNSCertificateObtainer struct {
}

func (d DNSCertificateObtainer) BeginCertificateOrder(ctx context.Context, client acme.Client, domains []string) (*acme.Order, error) {
	ids := []acme.AuthzID{}
	orderOpts := []acme.OrderOption{}

	order, err := client.AuthorizeOrder(ctx, ids, orderOpts...)

	if err != nil {
		return nil, err
	}

	return order, nil
}

func (d DNSCertificateObtainer) SolveAuthorizations(ctx context.Context, client acme.Client, orderURL string) (*[]byte, bool, error) {
	order, err := client.GetOrder(ctx, orderURL)

	if err != nil {
		return nil, false, err
	}

	domains := make([]string, len(order.Identifiers))
	for _, value := range order.Identifiers {
		domains = append(domains, value.Value)
	}
	
	if order.Status == acme.StatusPending {
		return nil, false, nil
	}
	
	if order.Status != acme.StatusReady {
		return nil, false, fmt.Errorf("order status is '%s'", order.Status)
	}

	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: domains[0],
			},
			DNSNames: domains[1:],
		},
		client.Key,
	)

	if err != nil {
		return nil, true, errors.Wrap(err, "failed to create csr")
	}

	cert, _, err := client.CreateOrderCert(ctx, order.CertURL, csr, false)

	if err != nil {
		return nil, true, errors.Wrap(err, "failed to create cert")
	}

	return &cert[0], true, nil
}

