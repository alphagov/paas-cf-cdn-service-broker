package healthchecks

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jarcoal/httpmock"

	"github.com/18F/cf-cdn-service-broker/config"
)

var _ = Describe("LetsEncrypt", func() {

	var (
		acmeURL = "https://acme-v01.api.mock-le.org/directory"
	)

	BeforeSuite(func() {
		httpmock.Activate()
	})

	BeforeEach(func() {
		httpmock.Reset()

		httpmock.RegisterResponder(
			"GET",
			acmeURL,
			httpmock.NewStringResponder(
				200, `{
                "key-change": "https://acme-v01.api.letsencrypt.org/acme/key-change",
                "meta": {
                  "caaIdentities": ["letsencrypt.org"],
                  "terms-of-service": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf",
                  "website": "https://letsencrypt.org"
                },
                "new-authz": "https://acme-v01.api.letsencrypt.org/acme/new-authz",
                "new-cert": "https://acme-v01.api.letsencrypt.org/acme/new-cert",
                "new-reg": "https://acme-v01.api.letsencrypt.org/acme/new-reg",
                "revoke-cert": "https://acme-v01.api.letsencrypt.org/acme/revoke-cert"
              }`,
			),
		)
	})

	AfterSuite(func() {
		httpmock.DeactivateAndReset()
	})

	It("Can new up a client", func() {
		err := LetsEncrypt(config.Settings{AcmeUrl: acmeURL})

		Expect(err).NotTo(HaveOccurred())
	})
})
