package letsencrypt

import (
	"context"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
)

type CertificateObtainer interface {
	BeginCertificateOrder(ctx context.Context, client ClientInterface, domains []string) (*acme.Order, error)
	SolveAuthorizations(ctx context.Context, client ClientInterface, orderURL string) (*[]byte, bool, error)
}

const ErrorOrderExpired = "order has expired"

func fetchOrderAuthorizationStatuses(order *acme.Order, client ClientInterface, ctx context.Context) (*map[string]string, error) {
	authStatuses := make(map[string]string, len(order.AuthzURLs))
	for _, authURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, "")

		if err != nil {
			return nil, errors.Wrapf(err, "failed to get authorization at %s", authURL)
		}
		authStatuses[authURL] = auth.Status
	}
	return &authStatuses, nil
}
