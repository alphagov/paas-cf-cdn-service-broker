package models

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/jarcoal/httpmock"
	"github.com/xenolf/lego/acme"
	jose "gopkg.in/square/go-jose.v2"
)

var _ = Describe("AcmeClient", func() {
	var (
		acmeBaseURL      = "https://acme-v01.api.mock-le.org"
		acmeDirectoryURL = acmeBaseURL + "/directory"
		acmeRegURL       = acmeBaseURL + "/acme/new-reg"
	)

	BeforeSuite(func() {
		httpmock.Activate()
	})

	BeforeEach(func() {
		httpmock.Reset()
	})

	AfterSuite(func() {
		httpmock.DeactivateAndReset()
	})

	It("Can new up a client", func() {
		settings := config.Settings{AcmeUrl: acmeDirectoryURL}
		rsaTestKey, _ := rsa.GenerateKey(rand.Reader, 2048)

		httpmock.RegisterResponder(
			"GET",
			acmeDirectoryURL,
			httpmock.NewStringResponder(
				200, `{
                "key-change": "https://acme-v01.api.mock-le.org/acme/key-change",
                "meta": {
                  "caaIdentities": ["mock-le.org"],
                  "terms-of-service": "https://mock-le.org/documents/LE-SA-v1.2-November-15-2017.pdf",
                  "website": "https://mock-le.org"
                },
                "new-authz": "https://acme-v01.api.mock-le.org/acme/new-authz",
                "new-cert": "https://acme-v01.api.mock-le.org/acme/new-cert",
                "new-reg": "https://acme-v01.api.mock-le.org/acme/new-reg",
                "revoke-cert": "https://acme-v01.api.mock-le.org/acme/revoke-cert"
              }`,
			),
		)

		httpmock.RegisterResponder(
			"HEAD",
			acmeDirectoryURL,
			httpmock.ResponderFromResponse(&http.Response{
				StatusCode: 200,
				Header: map[string][]string{
					"Replay-Nonce": []string{
						"WLdhKS-0oHQT_pSBszatf60A1OdtV3GImT2yGQJSzNA",
					},
				},
				Body: ioutil.NopCloser(strings.NewReader("")),
			}),
		)

		jwk := jose.JSONWebKey{Key: rsaTestKey}
		thumbprint, _ := jwk.MarshalJSON()

		httpmock.RegisterResponder(
			"POST",
			acmeRegURL,
			httpmock.ResponderFromResponse(&http.Response{
				StatusCode: 201,
				Header: map[string][]string{
					"Link": []string{
						acmeBaseURL + `/acme/new-authz>;rel="next"`,
						acmeBaseURL + `/LE-SA-v1.2-November-15-2017.pdf;rel="terms-of-service"`,
					},
					"Location": []string{acmeRegURL},
				},
				Body: ioutil.NopCloser(strings.NewReader(fmt.Sprintf(`{
						"key": %s,
						"contact": ["mailto:cert-admin@example.com","tel:+12025551212"]
					}`, string(thumbprint),
				))),
			}),
		)

		user := User{key: rsaTestKey}

		client, err := NewAcmeClient(
			settings, &user,
			s3.New(session.New(aws.NewConfig().WithRegion(settings.AwsDefaultRegion))),
			[]acme.Challenge{},
		)

		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(Equal(nil))
		Expect(user.GetRegistration()).NotTo(Equal(nil))
		Expect(user.GetRegistration().Body).NotTo(Equal(""))
	})
})
