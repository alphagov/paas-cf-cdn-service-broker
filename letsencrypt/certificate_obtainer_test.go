package letsencrypt_test

import (
	"code.cloudfoundry.org/lager"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/18F/cf-cdn-service-broker/letsencrypt/fakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/acme"
	"math/big"
	"time"

	. "github.com/18F/cf-cdn-service-broker/letsencrypt"
)

func makeDNSCertificateObtainer(challengerSolver ChallengeSolverInterface, logger lager.Logger) CertificateObtainerInterface {
	return DNSCertificateObtainer{
		Logger:          logger,
		ChallengeSolver: challengerSolver,
	}
}

var _ = Describe("DNSCertificateObtainer", func() {
	var (
		logger          lager.Logger
		challengeSolver *fakes.FakeChallengeSolver
		ctx             context.Context
	)

	BeforeSuite(func() {
		logger = lager.NewLogger("DnsCertificateObtainer")
		logger.RegisterSink(lager.NewWriterSink(GinkgoWriter, lager.INFO))

		ctx = context.Background()
	})

	BeforeEach(func() {
		challengeSolver = &fakes.FakeChallengeSolver{}
	})

	Describe("BeginCertificateOrder", func() {
		It("begins an order for the given domains using DNS authorizations", func() {
			client := fakes.FakeClientInterface{}
			client.AuthorizeOrderCalls(func(ctx context.Context, ids []acme.AuthzID, orderOpts ...acme.OrderOption) (*acme.Order, error) {
				return &acme.Order{
					Identifiers: ids,
				}, nil
			})
			domains := []string{
				"foo.bar",
				"bar.baz",
			}
			obtainer := makeDNSCertificateObtainer(challengeSolver, logger)

			order, err := obtainer.BeginCertificateOrder(ctx, &client, domains)

			Expect(err).ToNot(HaveOccurred())

			for index, id := range order.Identifiers {
				Expect(id.Value).To(Equal(domains[index]))
				Expect(id.Type).To(Equal("dns"))
			}
		})
	})

	Describe("SolveAuthorizations", func() {
		It("retrieves the certificate when the order is ready", func() {
			key, err := rsa.GenerateKey(rand.Reader, 1028)
			Expect(err).ToNot(HaveOccurred())

			client := fakes.FakeClientInterface{}
			client.GetKeyReturns(key)
			finalizeURL := "https://acme.example.org/certBundleBytes"
			readyOrder := acme.Order{
				Status: acme.StatusReady,
				Identifiers: []acme.AuthzID{
					{Type: "dns", Value: "foo.bar"},
					{Type: "dns", Value: "bar.baz"},
				},
				FinalizeURL: finalizeURL,
			}
			client.GetOrderReturns(&readyOrder, nil)

			// Generate certificate
			cert, certBytes, key := generateCertificate()
			certBundleBytes := [][]byte{
				certBytes,
				{60, 70, 80, 90, 100},
			}
			client.CreateOrderCertReturns(certBundleBytes, "certURL", nil)

			obtainer := makeDNSCertificateObtainer(challengeSolver, logger)
			replyCert, _, _, err := obtainer.SolveAuthorizations(ctx, &client, finalizeURL)

			Expect(err).ToNot(HaveOccurred())
			Expect(client.CreateOrderCertCallCount()).To(Equal(1))

			By("calling the endpoint specified in the order")
			_, expectedCertURL, _, _ := client.CreateOrderCertArgsForCall(0)
			Expect(expectedCertURL).To(Equal(finalizeURL))

			By("only parsing the first part of the returned certificate")
			Expect(replyCert.Subject.Organization).To(Equal(cert.Subject.Organization))
			Expect(replyCert.PublicKey).To(Equal(key.Public()))

		})

		It("returns a specific error when the order has expired", func() {
			client := fakes.FakeClientInterface{}
			expiredOrder := acme.Order{
				Status:      acme.StatusExpired,
				Identifiers: []acme.AuthzID{},
			}
			client.GetOrderReturns(&expiredOrder, nil)

			obtainer := makeDNSCertificateObtainer(challengeSolver, logger)

			_, _, triedChallenges, err := obtainer.SolveAuthorizations(ctx, &client, "order URL")
			Expect(triedChallenges).To(BeFalse())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(ErrorOrderExpired))
		})

		Describe("when the order is pending", func() {
			var pendingOrder acme.Order

			BeforeEach(func() {
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

				obtainer := makeDNSCertificateObtainer(challengeSolver, logger)
				_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
				Expect(err).ToNot(HaveOccurred())

				Expect(client.GetAuthorizationCallCount()).To(Equal(2))

				_, urlZero := client.GetAuthorizationArgsForCall(0)
				_, urlOne := client.GetAuthorizationArgsForCall(1)

				Expect(urlZero).To(Equal(authUrls[0]))
				Expect(urlOne).To(Equal(authUrls[1]))
			})

			It("when an authorization is valid, does not check its challenges", func() {
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

				obtainer := makeDNSCertificateObtainer(challengeSolver, logger)
				_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
				Expect(err).ToNot(HaveOccurred())

				Expect(client.GetAuthorizationCallCount()).To(Equal(1))
				Expect(client.AcceptCallCount()).To(Equal(0))
			})

			Describe("when an authorization is pending", func() {
				var (
					pendingAuth acme.Authorization
					client      fakes.FakeClientInterface
				)

				BeforeEach(func() {
					pendingAuth = acme.Authorization{Status: acme.StatusPending}
					pendingOrder.AuthzURLs = []string{"auth_url_one"}

					client = fakes.FakeClientInterface{}
					client.GetOrderReturns(&pendingOrder, nil)
					client.GetAuthorizationReturns(&pendingAuth, nil)

					client.AcceptCalls(func(ctx context.Context, challenge *acme.Challenge) (*acme.Challenge, error) {
						return challenge, nil
					})
				})

				It("does not try to solve valid challenges", func() {
					pendingAuth.Challenges = []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusValid},
					}

					obtainer := makeDNSCertificateObtainer(challengeSolver, logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(challengeSolver.TrySolveChallengeCallCount()).To(
						Equal(0),
						"TrySolveChallenge should have been called exactly zero times because there is one challenge and it is valid",
					)
				})

				It("does not try invalid challenges", func() {
					pendingAuth.Challenges = []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusInvalid},
					}

					obtainer := makeDNSCertificateObtainer(challengeSolver, logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(challengeSolver.TrySolveChallengeCallCount()).To(
						Equal(0),
						"TrySolveChallenge should have been called exactly zero times because there is one challenge and it is invalid",
					)
				})

				It("only tries to solve challenges which can be accepted by the challenge solver", func() {
					pendingAuth.Challenges = []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusPending, Type: ChallengeTypeDNS},
						&acme.Challenge{Status: acme.StatusPending, Type: ChallengeTypeHTTP},
						&acme.Challenge{Status: acme.StatusPending, Type: ChallengeTypeTLS},
					}

					challengeSolver.AcceptCalls(func(challenge *acme.Challenge) bool {
						if *pendingAuth.Challenges[0] == *challenge {
							return true
						}

						return false
					})
					challengeSolver.TrySolveChallengeReturns(true, nil)

					obtainer := makeDNSCertificateObtainer(challengeSolver, logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(challengeSolver.TrySolveChallengeCallCount()).To(
						Equal(1),
						"TrySolveChallenge should have been called exactly once because there is only one acceptable challenge",
					)

					_, challenge, _ := challengeSolver.TrySolveChallengeArgsForCall(0)
					Expect(challenge).To(Equal(pendingAuth.Challenges[0]))
				})

				It("tries to solve challenges in the pending state", func() {
					pendingAuth.Challenges = []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusPending},
					}

					challengeSolver.AcceptReturns(true)
					challengeSolver.TrySolveChallengeReturns(true, nil)

					obtainer := makeDNSCertificateObtainer(challengeSolver, logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(challengeSolver.TrySolveChallengeCallCount()).To(
						Equal(1),
						"TrySolveChallenge should have been called exactly once times there is one challenge and it is pending",
					)

					_, challenge := client.AcceptArgsForCall(0)
					Expect(challenge).To(Equal(pendingAuth.Challenges[0]))
				})

				It("tries to solve challenges in the processing state", func() {
					pendingAuth.Challenges = []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusProcessing},
					}

					challengeSolver.AcceptReturns(true)
					challengeSolver.TrySolveChallengeReturns(true, nil)

					obtainer := makeDNSCertificateObtainer(challengeSolver, logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(challengeSolver.TrySolveChallengeCallCount()).To(
						Equal(1),
						"TrySolveChallenge should have been called exactly once times there is one challenge and it is pending",
					)

					_, challenge := client.AcceptArgsForCall(0)
					Expect(challenge).To(Equal(pendingAuth.Challenges[0]))
				})

				It("does not accept a challenge which hasn't been solved", func() {
					pendingAuth.Challenges = []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusPending, Type: ChallengeTypeDNS},
					}
					challengeSolver.AcceptReturns(true)
					challengeSolver.TrySolveChallengeReturns(false, nil)

					obtainer := makeDNSCertificateObtainer(challengeSolver, logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(client.AcceptCallCount()).To(
						Equal(0),
						"Accept should have been called exactly zero times because the challenge was not solved",
					)
				})

				It("accepts challenges which were solved", func() {
					pendingAuth.Challenges = []*acme.Challenge{
						&acme.Challenge{Status: acme.StatusPending, Type: ChallengeTypeDNS},
						&acme.Challenge{Status: acme.StatusPending, Type: ChallengeTypeHTTP},
						&acme.Challenge{Status: acme.StatusPending, Type: ChallengeTypeTLS},
					}

					challengeSolver.AcceptReturns(true)
					challengeSolver.TrySolveChallengeCalls(func(authorization *acme.Authorization, challenge *acme.Challenge, client ClientInterface) (bool, error) {
						if *challenge == *pendingAuth.Challenges[0] {
							return true, nil
						}

						return false, nil
					})

					obtainer := makeDNSCertificateObtainer(challengeSolver, logger)
					_, _, _, err := obtainer.SolveAuthorizations(ctx, &client, "order url")
					Expect(err).ToNot(HaveOccurred())

					Expect(challengeSolver.TrySolveChallengeCallCount()).To(
						Equal(3),
						"TrySolveChallenge should have been called exactly three times because all three challenges are acceptable",
					)

					_, challenge := client.AcceptArgsForCall(0)
					Expect(challenge).To(Equal(pendingAuth.Challenges[0]), "Accept should have been called with the challenge which was solved")
				})
			})
		})
	})
})

func generateCertificate() (*x509.Certificate, []byte, *rsa.PrivateKey) {
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(10000),
		Subject: pkix.Name{
			Organization: []string{"GOV.UK PaaS"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	Expect(err).ToNot(HaveOccurred())
	publicKey := &privateKey.PublicKey
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, publicKey, privateKey)
	//pemBytes := bytes.Buffer{}
	//err = pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	//Expect(err).ToNot(HaveOccurred())

	return certTemplate, certBytes, privateKey
}
