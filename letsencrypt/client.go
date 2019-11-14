package letsencrypt

import (
	"context"
	"crypto"
	"crypto/tls"
	"golang.org/x/crypto/acme"
	"time"
)

// This interface is extracted from the golang.org/x/crypto/acme package
// in order to provide  an interface to fake for testing.
// It has additional methods which replace property access on the original client struct.
//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -o fakes/FakeClient.go . ClientInterface
type ClientInterface interface {
	Discover(ctx context.Context) (acme.Directory, error)
	CreateCert(ctx context.Context, csr []byte, exp time.Duration, bundle bool) (der [][]byte, certURL string, err error)
	FetchCert(ctx context.Context, url string, bundle bool) ([][]byte, error)
	RevokeCert(ctx context.Context, key crypto.Signer, cert []byte, reason acme.CRLReasonCode) error
	Register(ctx context.Context, acct *acme.Account, prompt func(tosURL string) bool) (*acme.Account, error)
	GetReg(ctx context.Context, url string) (*acme.Account, error)
	UpdateReg(ctx context.Context, acct *acme.Account) (*acme.Account, error)
	Authorize(ctx context.Context, domain string) (*acme.Authorization, error)
	AuthorizeIP(ctx context.Context, ipaddr string) (*acme.Authorization, error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	RevokeAuthorization(ctx context.Context, url string) error
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	GetChallenge(ctx context.Context, url string) (*acme.Challenge, error)
	Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	DNS01ChallengeRecord(token string) (string, error)
	HTTP01ChallengeResponse(token string) (string, error)
	HTTP01ChallengePath(token string) string
	TLSSNI01ChallengeCert(token string, opt ...acme.CertOption) (cert tls.Certificate, name string, err error)
	TLSSNI02ChallengeCert(token string, opt ...acme.CertOption) (cert tls.Certificate, name string, err error)
	TLSALPN01ChallengeCert(token, domain string, opt ...acme.CertOption) (cert tls.Certificate, err error)
	DeactivateReg(ctx context.Context) error
	AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error)
	GetOrder(ctx context.Context, url string) (*acme.Order, error)
	WaitOrder(ctx context.Context, url string) (*acme.Order, error)
	CreateOrderCert(ctx context.Context, url string, csr []byte, bundle bool) (der [][]byte, certURL string, err error)

	// Property accessors
	GetKey() crypto.Signer
}

// Client is a decorator around an acme.Client instance
// which implements the accessor methods
type Client struct {
	acmeClient acme.Client
}

func (c Client) Discover(ctx context.Context) (acme.Directory, error) {
	return c.acmeClient.Discover(ctx)
}

func (c Client) CreateCert(ctx context.Context, csr []byte, exp time.Duration, bundle bool) (der [][]byte, certURL string, err error) {
	return c.acmeClient.CreateCert(ctx, csr, exp, bundle)
}

func (c Client) FetchCert(ctx context.Context, url string, bundle bool) ([][]byte, error) {
	return c.acmeClient.FetchCert(ctx, url, bundle)
}

func (c Client) RevokeCert(ctx context.Context, key crypto.Signer, cert []byte, reason acme.CRLReasonCode) error {
	return c.acmeClient.RevokeCert(ctx, key, cert, reason)
}

func (c Client) Register(ctx context.Context, acct *acme.Account, prompt func(tosURL string) bool) (*acme.Account, error) {
	return c.acmeClient.Register(ctx, acct, prompt)
}

func (c Client) GetReg(ctx context.Context, url string) (*acme.Account, error) {
	return c.acmeClient.GetReg(ctx, url)
}

func (c Client) UpdateReg(ctx context.Context, acct *acme.Account) (*acme.Account, error) {
	return c.acmeClient.UpdateReg(ctx, acct)
}

func (c Client) Authorize(ctx context.Context, domain string) (*acme.Authorization, error) {
	return c.acmeClient.Authorize(ctx, domain)
}

func (c Client) AuthorizeIP(ctx context.Context, ipaddr string) (*acme.Authorization, error) {
	return c.acmeClient.AuthorizeIP(ctx, ipaddr)
}

func (c Client) GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return c.acmeClient.GetAuthorization(ctx, url)
}

func (c Client) RevokeAuthorization(ctx context.Context, url string) error {
	return c.acmeClient.RevokeAuthorization(ctx, url)
}

func (c Client) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return c.acmeClient.WaitAuthorization(ctx, url)
}

func (c Client) GetChallenge(ctx context.Context, url string) (*acme.Challenge, error) {
	return c.acmeClient.GetChallenge(ctx, url)
}

func (c Client) Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	return c.acmeClient.Accept(ctx, chal)
}

func (c Client) DNS01ChallengeRecord(token string) (string, error) {
	return c.acmeClient.DNS01ChallengeRecord(token)
}

func (c Client) HTTP01ChallengeResponse(token string) (string, error) {
	return c.acmeClient.HTTP01ChallengeResponse(token)
}

func (c Client) HTTP01ChallengePath(token string) string {
	return c.acmeClient.HTTP01ChallengePath(token)
}

func (c Client) TLSSNI01ChallengeCert(token string, opt ...acme.CertOption) (cert tls.Certificate, name string, err error) {
	return c.acmeClient.TLSSNI01ChallengeCert(token, opt...)
}

func (c Client) TLSSNI02ChallengeCert(token string, opt ...acme.CertOption) (cert tls.Certificate, name string, err error) {
	return c.acmeClient.TLSSNI02ChallengeCert(token, opt...)
}

func (c Client) TLSALPN01ChallengeCert(token, domain string, opt ...acme.CertOption) (cert tls.Certificate, err error) {
	return c.acmeClient.TLSALPN01ChallengeCert(token, domain, opt...)
}

func (c Client) DeactivateReg(ctx context.Context) error {
	return c.acmeClient.DeactivateReg(ctx)
}

func (c Client) AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error) {
	return c.acmeClient.AuthorizeOrder(ctx, id, opt...)
}

func (c Client) GetOrder(ctx context.Context, url string) (*acme.Order, error) {
	return c.acmeClient.GetOrder(ctx, url)
}

func (c Client) WaitOrder(ctx context.Context, url string) (*acme.Order, error) {
	return c.acmeClient.WaitOrder(ctx, url)
}

func (c Client) CreateOrderCert(ctx context.Context, url string, csr []byte, bundle bool) (der [][]byte, certURL string, err error) {
	return c.acmeClient.CreateOrderCert(ctx, url, csr, bundle)
}

func (c Client) GetKey() crypto.Signer {
	return c.acmeClient.Key
}

