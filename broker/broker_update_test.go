package broker

import (
	"context"
	"encoding/json"
	"errors"

	"code.cloudfoundry.org/lager"
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/pivotal-cf/brokerapi"

	cfmock "github.com/18F/cf-cdn-service-broker/cf/mocks"
	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/models/mocks"
	"github.com/18F/cf-cdn-service-broker/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Update", func() {
	var (
		manager  mocks.RouteManagerIface
		broker   *CdnServiceBroker
		cfClient cfmock.Client
		settings config.Settings
		logger   lager.Logger
		ctx      context.Context
	)

	BeforeEach(func() {
		manager = mocks.RouteManagerIface{}
		cfClient = cfmock.Client{}
		settings = config.Settings{DefaultOrigin: "origin.cloud.gov"}
		broker = New(&manager, &cfClient, settings, logger)
		ctx = context.Background()
	})

	It("returns an error when updated without options", func() {
		details := brokerapi.UpdateDetails{
			RawParameters: json.RawMessage(`{"origin": ""}`),
		}
		_, err := broker.Update(ctx, "", details, true)

		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("must pass non-empty `domain` or `origin`")))
	})

	It("successfully updates when updated with only domain", func() {
		details := brokerapi.UpdateDetails{
			RawParameters: json.RawMessage(`{"domain": "domain.gov"}`),
		}
		manager.On("Update", "", "domain.gov", "origin.cloud.gov", "", false, utils.Headers{"Host": true}, true).Return(nil)
		cfClient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
		_, err := broker.Update(ctx, "", details, true)

		Expect(err).NotTo(HaveOccurred())
	})

	It("successfully updates when updated with only origin", func() {
		details := brokerapi.UpdateDetails{
			RawParameters: json.RawMessage(`{"origin": "origin.gov"}`),
		}
		manager.On("Update", "", "", "origin.gov", "", false, utils.Headers{}, true).Return(nil)
		cfClient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
		_, err := broker.Update(ctx, "", details, true)

		Expect(err).NotTo(HaveOccurred())
	})

	It("successfully updates", func() {
		details := brokerapi.UpdateDetails{
			RawParameters: json.RawMessage(`{
			"insecure_origin": true,
			"domain": "domain.gov",
			"path": "."
		}`),
		}
		manager.On("Update", "", "domain.gov", "origin.cloud.gov", ".", true, utils.Headers{"Host": true}, true).Return(nil)
		cfClient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
		_, err := broker.Update(ctx, "", details, true)

		Expect(err).NotTo(HaveOccurred())
	})

	It("returns an error when update is called without a cf domain", func() {
		details := brokerapi.UpdateDetails{
			PreviousValues: brokerapi.PreviousValues{
				OrgID: "dfb39134-ab7d-489e-ae59-4ed5c6f42fb5",
			},
			RawParameters: json.RawMessage(`{"domain": "domain.gov"}`),
		}
		manager.On("Update", "", "domain.gov", "origin.cloud.gov", ".", true, utils.Headers{"Host": true}, true).Return(nil)
		cfClient.On("GetOrgByGuid", "dfb39134-ab7d-489e-ae59-4ed5c6f42fb5").Return(cfclient.Org{Name: "my-org"}, nil)
		cfClient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, errors.New("bad"))
		_, err := broker.Update(ctx, "", details, true)

		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("cf create-domain")))
	})

	Context("Header Forwarding", func() {
		BeforeEach(func() {
			cfClient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
		})

		It("successfully updates with duplicated host header", func() {
			expectedHeaders := utils.Headers{"Host": true}
			manager.On("Update", "", "domain.gov", "origin.cloud.gov", ".", true, expectedHeaders, true).Return(nil)
			details := brokerapi.UpdateDetails{
				RawParameters: json.RawMessage(`{
					"insecure_origin": true,
					"domain": "domain.gov",
					"path": ".",
					"headers": ["Host"]
				}`),
			}
			_, err := broker.Update(ctx, "", details, true)

			Expect(err).NotTo(HaveOccurred())
		})

		It("successfully updates with a single header", func() {
			expectedHeaders := utils.Headers{"User-Agent": true, "Host": true}
			manager.On("Update", "", "domain.gov", "origin.cloud.gov", ".", true, expectedHeaders, true).Return(nil)
			details := brokerapi.UpdateDetails{
				RawParameters: json.RawMessage(`{
					"insecure_origin": true,
					"domain": "domain.gov",
					"path": ".",
					"headers": ["User-Agent"]
				}`),
			}
			_, err := broker.Update(ctx, "", details, true)

			Expect(err).NotTo(HaveOccurred())
		})

		It("successfully updates with all headers using wildcard", func() {
			expectedHeaders := utils.Headers{"*": true}
			manager.On("Update", "", "domain.gov", "origin.cloud.gov", ".", true, expectedHeaders, true).Return(nil)
			details := brokerapi.UpdateDetails{
				RawParameters: json.RawMessage(`{
					"insecure_origin": true,
					"domain": "domain.gov",
					"path": ".",
					"headers": ["*"]
				}`),
			}
			_, err := broker.Update(ctx, "", details, true)

			Expect(err).NotTo(HaveOccurred())
		})

		It("successfully updates with nine headers", func() {
			expectedHeaders := utils.Headers{"One": true, "Two": true, "Three": true, "Four": true, "Five": true, "Six": true, "Seven": true, "Eight": true, "Nine": true, "Host": true}
			manager.On("Update", "", "domain.gov", "origin.cloud.gov", ".", true, expectedHeaders, true).Return(nil)
			details := brokerapi.UpdateDetails{
				RawParameters: json.RawMessage(`{
					"insecure_origin": true,
					"domain": "domain.gov",
					"path": ".",
					"headers": ["One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"]
				}`),
			}
			_, err := broker.Update(ctx, "", details, true)

			Expect(err).NotTo(HaveOccurred())
		})

		It("returns an error when given wildcard and normal header", func() {
			expectedHeaders := utils.Headers{"*": true}
			manager.On("Update", "", "domain.gov", "origin.cloud.gov", ".", true, expectedHeaders, true).Return(errors.New("fail"))
			details := brokerapi.UpdateDetails{
				RawParameters: json.RawMessage(`{
			"insecure_origin": true,
			"domain": "domain.gov",
			"path": ".",
			"headers": ["*", "User-Agent"]
		}`),
			}
			_, err := broker.Update(ctx, "", details, true)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("must not pass whitelisted headers alongside wildcard")))
		})

		It("returns an error when given more than ten headers", func() {
			expectedHeaders := utils.Headers{"One": true, "Two": true, "Three": true, "Four": true, "Five": true, "Six": true, "Seven": true, "Eight": true, "Nine": true, "Ten": true, "Host": true}
			manager.On("Update", "", "domain.gov", "origin.cloud.gov", ".", true, expectedHeaders, true).Return(errors.New("fail"))
			details := brokerapi.UpdateDetails{
				RawParameters: json.RawMessage(`{
			"insecure_origin": true,
			"domain": "domain.gov",
			"path": ".",
			"headers": ["One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten"]
		}`),
			}
			_, err := broker.Update(ctx, "", details, true)

			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("must not set more than 10 headers; got 11")))
		})
	})
})
