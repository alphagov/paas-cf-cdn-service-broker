package healthchecks

import (
	"context"

	"github.com/18F/cf-cdn-service-broker/config"
	"golang.org/x/crypto/acme"
)

func LetsEncrypt(settings config.Settings) error {
	acmeClient := acme.Client{}

	if settings.AcmeUrl != "" {
		acmeClient.DirectoryURL = settings.AcmeUrl
	}

	_, err := acmeClient.Discover(context.Background())

	return err
}
