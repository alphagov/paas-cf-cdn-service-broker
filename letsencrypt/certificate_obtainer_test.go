package letsencrypt_test

import (
	"code.cloudfoundry.org/lager"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"github.com/18F/cf-cdn-service-broker/letsencrypt/fakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/acme"

	. "github.com/18F/cf-cdn-service-broker/letsencrypt"
)

var _ = Describe("DNSCertificateObtainer", func() {
	var (
		logger lager.Logger
		ctx context.Context
	)


	BeforeSuite(func(){
		logger = lager.NewLogger("DnsCertificateObtainer")
		logger.RegisterSink(lager.NewWriterSink(GinkgoWriter, lager.INFO))

		ctx = context.Background()
	})

	Describe("BeginCertificateOrder", func() {
		It("begins an order for the given domains using DNS authorizations", func(){
			client := fakes.FakeClientInterface{}
			client.AuthorizeOrderCalls(func(ctx context.Context, ids []acme.AuthzID, orderOpts ...acme.OrderOption) (*acme.Order, error) {
				return &acme.Order{
					Identifiers: ids,
				}, nil
			})
			domains := []string {
				"foo.bar",
				"bar.baz",
			}
			obtainer := NewDNSCertificateObtainer(logger)

			order, err := obtainer.BeginCertificateOrder(ctx, &client, domains)

			Expect(err).ToNot(HaveOccurred())

			for index, id := range order.Identifiers {
				Expect(id.Value).To(Equal(domains[index]))
				Expect(id.Type).To(Equal("dns"))
			}
		})
	})

	Describe("SolveAuthorizations", func() {
		It("retrieves the certificate when the order is ready", func(){
			key, err := rsa.GenerateKey(rand.Reader, 1028)
			Expect(err).ToNot(HaveOccurred())


			client := fakes.FakeClientInterface{}
			client.GetKeyReturns(key)
			certUrl := "https://acme.example.org/cert"
			readyOrder := acme.Order{
				Status: acme.StatusReady,
				Identifiers: []acme.AuthzID{
					{Type: "dns", Value: "foo.bar"},
					{Type: "dns", Value: "bar.baz"},
				},
				CertURL: certUrl,
			}
			client.GetOrderReturns(&readyOrder, nil)

			cert := [][]byte{
				{10, 20, 30, 40, 50},
				{60, 70, 80, 90, 100},
			}
			client.CreateOrderCertReturns(cert, "certURL", nil)

			obtainer := NewDNSCertificateObtainer(logger)
			replyCert, _, _, err := obtainer.SolveAuthorizations(ctx, &client, certUrl)

			Expect(err).ToNot(HaveOccurred())
			Expect(client.CreateOrderCertCallCount()).To(Equal(1))

			By("calling the endpoint specified in the order")
			_, expectedCertURL, _, _ := client.CreateOrderCertArgsForCall(0)
			Expect(expectedCertURL).To(Equal(certUrl))

			By("only taking the first part of the returned certificate")
			// only the first part of the certificate 2d byte slice returned by
			// the ACME provider is significant because we don't get the bundle
			Expect(*replyCert).To(Equal(cert[0]))

		})

		It("returns a specific error when the order has expired", func(){
			client := fakes.FakeClientInterface{}
			expiredOrder := acme.Order{
				Status: acme.StatusExpired,
				Identifiers: []acme.AuthzID{},
			}
			client.GetOrderReturns(&expiredOrder, nil)

			obtainer := NewDNSCertificateObtainer(logger)

			_, _, triedChallenges, err := obtainer.SolveAuthorizations(ctx, &client, "order URL")
			Expect(triedChallenges).To(BeFalse())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(ErrorOrderExpired))
		})

		Describe("when the order is pending", func() {
			var pendingOrder acme.Order

			BeforeEach(func(){
				pendingOrder = acme.Order{Status: acme.StatusPending}
			})

			It("requests each authorization in turn", func() {
				authUrls := []string{"auth_url_1", "auth_url_2"}
				authz := []*acme.Authorization{
					&acme.Authorization{Status: acme.StatusValid, Challenges: []*acme.Challenge{}},
					&acme.Authorization{Status: acme.StatusInvalid, Challenges: []*acme.Challenge{}},
				}

				pendingOrder.AuthzURLs = authUrls

				client := fakes.FakeClientInterface{}
				client.GetOrderReturns(&pendingOrder, nil)
				client.GetAuthorizationReturnsOnCall(0, authz[0], nil)
				client.GetAuthorizationReturnsOnCall(1, authz[1], nil)

				obtainer := NewDNSCertificateObtainer(logger)
				_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
				Expect(err).ToNot(HaveOccurred())

				Expect(client.GetAuthorizationCallCount()).To(Equal(2))

				_, urlZero := client.GetAuthorizationArgsForCall(0)
				_, urlOne := client.GetAuthorizationArgsForCall(1)

				Expect(urlZero).To(Equal(authUrls[0]))
				Expect(urlOne).To(Equal(authUrls[1]))
			})

			It("when an authorization is valid, does not check its challenges", func(){
				auth := acme.Authorization{
					Status: acme.StatusValid,
					Challenges: []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusPending},
					},
				}

				pendingOrder.AuthzURLs = []string{"auth_url"}

				client := fakes.FakeClientInterface{}
				client.GetOrderReturns(&pendingOrder, nil)
				client.GetAuthorizationReturns(&auth, nil)

				obtainer := NewDNSCertificateObtainer(logger)
				_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
				Expect(err).ToNot(HaveOccurred())

				Expect(client.GetAuthorizationCallCount()).To(Equal(1))
				Expect(client.AcceptCallCount()).To(Equal(0))
			})

			Describe("when an authorization is pending", func(){
				var (
					pendingAuth acme.Authorization
					client fakes.FakeClientInterface
				)

				BeforeEach(func(){
					pendingAuth = acme.Authorization{Status: acme.StatusPending}
					pendingOrder.AuthzURLs = []string{"auth_url_one"}

					client = fakes.FakeClientInterface{}
					client.GetOrderReturns(&pendingOrder, nil)
					client.GetAuthorizationReturns(&pendingAuth, nil)

					client.AcceptCalls(func(ctx context.Context, challenge *acme.Challenge) (*acme.Challenge, error) {
						return challenge, nil
					})
				})

				It("does not try to solve valid challenges", func(){
					pendingAuth.Challenges = []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusValid},
					}

					obtainer := NewDNSCertificateObtainer(logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(client.AcceptCallCount()).To(
						Equal(0),
						"Accept should have been called exactly zero times because there is one challenge and it is valid",
					)
				})

				It("does not try invalid challenges", func(){
					pendingAuth.Challenges = []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusInvalid},
					}

					obtainer := NewDNSCertificateObtainer(logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(client.AcceptCallCount()).To(
						Equal(0),
						"Accept should have been called exactly zero times because there is one challenge and it is invalid",
					)
				})

				It("only tries to solve DNS-01 challenges", func(){
					pendingAuth.Challenges = []*acme.Challenge {
						&acme.Challenge{Status: acme.StatusPending, Type: ChallengeTypeDNS},
						&acme.Challenge{Status: acme.StatusPending, Type: ChallengeTypeHTTP},
						&acme.Challenge{Status: acme.StatusPending, Type: ChallengeTypeTLS},
					}

					obtainer := NewDNSCertificateObtainer(logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(client.AcceptCallCount()).To(
						Equal(1),
						"Accept should have been called exactly once because there is only one DNS challenge",
					)

					_, challenge := client.AcceptArgsForCall(0)
					Expect(challenge).To(Equal(pendingAuth.Challenges[0]))
				})

				It("tries to solve challenges in the pending state", func(){
					pendingAuth.Challenges = []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusPending},
					}

					obtainer := NewDNSCertificateObtainer(logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(client.AcceptCallCount()).To(
						Equal(1),
						"Accept should have been called exactly once times there is one challenge and it is pending",
					)

					_, challenge := client.AcceptArgsForCall(0)
					Expect(challenge).To(Equal(pendingAuth.Challenges[0]))
				})

				It("tries to solve challenges in the processing state", func(){
					pendingAuth.Challenges = []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusProcessing},
					}

					obtainer := NewDNSCertificateObtainer(logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(client.AcceptCallCount()).To(
						Equal(1),
						"Accept should have been called exactly once times there is one challenge and it is processing",
					)

					_, challenge := client.AcceptArgsForCall(0)
					Expect(challenge).To(Equal(pendingAuth.Challenges[0]))
				})
			})
		})
	})
})
