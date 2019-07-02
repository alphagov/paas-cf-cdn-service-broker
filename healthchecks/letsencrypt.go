package healthchecks

import (
	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/utils"
)

func LetsEncrypt(settings config.Settings) error {
	user := utils.User{}
	user.SetPrivateKey("cheese")

	_, err := utils.NewAcmeClient(
		config.Settings{AcmeUrl: "https://acme-v01.api.letsencrypt.org/directory"},
		&user,
	)

	return err
}
