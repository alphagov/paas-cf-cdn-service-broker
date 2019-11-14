package letsencrypt

import (
	"code.cloudfoundry.org/lager"
	"context"
	"github.com/18F/cf-cdn-service-broker/utils"
	"golang.org/x/crypto/acme"
)

type AccountCreatorInterface interface {
	EnsureAccount(ctx context.Context, user utils.User) (*acme.Account, *acme.Client, error)
}

type AccountCreator struct {
	logger lager.Logger
}

// EnsureAccount creates/retrieves an acme registration from Let's Encrypt.
// Submitting a registration to LE with a key that already exists merely retrieves the account.
// See: https://letsencrypt.org/docs/account-id/
func (a AccountCreator) EnsureAccount(ctx context.Context, user utils.User) (*acme.Account, *acme.Client, error) {
	logSess := a.logger.Session("ensure-account")
	k := user.GetPrivateKey()
	client := &acme.Client{
		Key: &k,
	}
	account := &acme.Account{
		Contact: []string{user.Email},
	}

	logSess.Info("register")
	account, err := client.Register(ctx, account, acme.AcceptTOS)
	if err != nil {
		logSess.Error("register-error", err)
		return nil, nil, err
	}

	logSess.Info("register-success")
	return account, client, nil
}

