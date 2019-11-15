package letsencrypt

import (
	"code.cloudfoundry.org/lager"
	"context"
	"fmt"
	"github.com/18F/cf-cdn-service-broker/utils"
	"golang.org/x/crypto/acme"
)

type AccountCreatorInterface interface {
	EnsureAccount(ctx context.Context, user utils.User) (*acme.Account, *ClientInterface, error)
}

type AccountCreator struct {
	logger lager.Logger
}

func NewAccountCreator(logger lager.Logger) AccountCreatorInterface {
	return AccountCreator{logger: logger}
}

// EnsureAccount creates/retrieves an acme registration from Let's Encrypt.
// Submitting a registration to LE with a key that already exists merely retrieves the account.
// See: https://letsencrypt.org/docs/account-id/
func (a AccountCreator) EnsureAccount(ctx context.Context, user utils.User) (*acme.Account, *ClientInterface, error) {
	logSess := a.logger.Session("ensure-account")
	k := user.GetPrivateKey()
	client := &acme.Client{
		Key: &k,
	}
	account := &acme.Account{
		Contact: []string{fmt.Sprintf("mailto:%s", user.Email)},
	}

	logSess.Info("register")
	account, err := client.Register(ctx, account, acme.AcceptTOS)
	if err != nil {
		logSess.Error("register-error", err)
		return nil, nil, err
	}

	logSess.Info("register-success")
	decoratedClient := decorateClient(*client)
	return account, &decoratedClient, nil
}

