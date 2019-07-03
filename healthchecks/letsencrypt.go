package healthchecks

import (
	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/utils"
)

func LetsEncrypt(settings config.Settings) error {
	user := utils.User{}
	user.SetPrivateKey("cheese")

	if settings.AcmeUrl == "" {
		settings.AcmeUrl = "https://acme-v01.api.letsencrypt.org/directory"
	}

	_, err := utils.NewAcmeClient(settings, &user)

	return err
}
