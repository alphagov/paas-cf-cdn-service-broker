package broker

import (
	"context"
	"errors"

	"code.cloudfoundry.org/lager"
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/pivotal-cf/brokerapi"

	cfmock "github.com/18F/cf-cdn-service-broker/cf/mocks"
	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/models"
	"github.com/18F/cf-cdn-service-broker/models/mocks"
	"github.com/18F/cf-cdn-service-broker/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Provision", func() {
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
		cfClient.On("GetOrgByGuid", "dfb39134-ab7d-489e-ae59-4ed5c6f42fb5").Return(cfclient.Org{Name: "my-org"}, nil)
	})

	It("returns an error for synchronous provisioning", func() {
		_, err := broker.Provision(ctx, "", brokerapi.ProvisionDetails{}, false)

		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(brokerapi.ErrAsyncRequired))
	})

	It("returns an error for provisioning without details", func() {
		_, err := broker.Provision(ctx, "", brokerapi.ProvisionDetails{}, true)

		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("must be invoked with configuration parameters")))
	})

	It("returns an error for provisioning without options", func() {
		details := brokerapi.ProvisionDetails{RawParameters: []byte(`{}`)}
		_, err := broker.Provision(ctx, "", details, true)

		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("must pass non-empty `domain`")))
	})

	It("returns an error if the instance already exists", func() {
		route := &models.Route{State: models.Provisioned}
		cfClient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
		manager.On("Get", "123").Return(route, nil)
		details := brokerapi.ProvisionDetails{RawParameters: []byte(`{"domain": "domain.gov"}`)}
		_, err := broker.Provision(ctx, "123", details, true)

		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(brokerapi.ErrInstanceAlreadyExists))
	})

	It("does not return an error when provisioning correctly", func() {
		manager.On("Get", "123").Return(&models.Route{}, errors.New("not found"))
		route := &models.Route{State: models.Provisioning}
		cfClient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
		manager.On("Create", "123", "domain.gov", "origin.cloud.gov", "", false, utils.Headers{"Host": true}, true,
			map[string]string{"Organization": "", "Space": "", "Service": "", "Plan": ""}).Return(route, nil)
		details := brokerapi.ProvisionDetails{RawParameters: []byte(`{"domain": "domain.gov"}`)}
		_, err := broker.Provision(ctx, "123", details, true)

		Expect(err).NotTo(HaveOccurred())
	})

	It("does not return an error when provisioning correctly with a custom origin", func() {
		manager.On("Get", "123").Return(&models.Route{}, errors.New("not found"))
		route := &models.Route{State: models.Provisioning}
		manager.On("Create", "123", "domain.gov", "custom.cloud.gov", "", false, utils.Headers{}, true,
			map[string]string{"Organization": "", "Space": "", "Service": "", "Plan": ""}).Return(route, nil)
		details := brokerapi.ProvisionDetails{RawParameters: []byte(`{"domain": "domain.gov", "origin": "custom.cloud.gov"}`)}
		_, err := broker.Provision(ctx, "123", details, true)

		Expect(err).NotTo(HaveOccurred())
	})

	It("returns an error when provisioning without a cf domain", func() {
		cfClient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, errors.New("fail"))
		details := brokerapi.ProvisionDetails{
			OrganizationGUID: "dfb39134-ab7d-489e-ae59-4ed5c6f42fb5",
			RawParameters:    []byte(`{"domain": "domain.gov"}`),
		}
		_, err := broker.Provision(ctx, "123", details, true)

		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("cf create-domain")))
	})

	It("returns an error when provisioning multiple domains when one does not exist ", func() {
		cfClient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
		cfClient.On("GetDomainByName", "domain2.gov").Return(cfclient.Domain{}, errors.New("fail"))
		details := brokerapi.ProvisionDetails{
			OrganizationGUID: "dfb39134-ab7d-489e-ae59-4ed5c6f42fb5",
			RawParameters:    []byte(`{"domain": "domain.gov,domain2.gov"}`),
		}
		_, err := broker.Provision(ctx, "123", details, true)

		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("Domain does not exist")))
		Expect(err).To(MatchError(ContainSubstring("domain2.gov")))
		Expect(err).NotTo(MatchError(ContainSubstring("domain.gov")))
	})

	It("returns an error when provisioning multiple domains when multiple domains do not exist ", func() {
		cfClient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
		cfClient.On("GetDomainByName", "domain2.gov").Return(cfclient.Domain{}, errors.New("fail"))
		cfClient.On("GetDomainByName", "domain3.gov").Return(cfclient.Domain{}, errors.New("fail"))
		details := brokerapi.ProvisionDetails{
			OrganizationGUID: "dfb39134-ab7d-489e-ae59-4ed5c6f42fb5",
			RawParameters:    []byte(`{"domain": "domain.gov,domain2.gov,domain3.gov"}`),
		}
		_, err := broker.Provision(ctx, "123", details, true)

		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("Multiple domains do not exist")))
		Expect(err).To(MatchError(ContainSubstring("domain2.gov")))
		Expect(err).To(MatchError(ContainSubstring("domain3.gov")))
		Expect(err).NotTo(MatchError(ContainSubstring("domain.gov")))
	})

	Context("Header Forwarding", func() {
		BeforeEach(func() {
			manager.On("Get", "123").Return(&models.Route{}, errors.New("not found"))
			cfClient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
		})

		It("successfully provisions when forwarding duplicate host header", func() {
			expectedHeaders := utils.Headers{"Host": true}
			route := &models.Route{State: models.Provisioning}
			manager.On("Create", "123", "domain.gov", "origin.cloud.gov", "", false, expectedHeaders, true,
				map[string]string{"Organization": "", "Space": "", "Service": "", "Plan": ""}).Return(route, nil)

			details := brokerapi.ProvisionDetails{
				RawParameters: []byte(`{"domain": "domain.gov", "headers": ["Host"]}`),
			}
			_, err := broker.Provision(ctx, "123", details, true)

			Expect(err).NotTo(HaveOccurred())
		})

		It("successfully provisions when forwarding a single header", func() {
			expectedHeaders := utils.Headers{"User-Agent": true, "Host": true}
			route := &models.Route{State: models.Provisioning}
			manager.On("Create", "123", "domain.gov", "origin.cloud.gov", "", false, expectedHeaders, true,
				map[string]string{"Organization": "", "Space": "", "Service": "", "Plan": ""}).Return(route, nil)
			details := brokerapi.ProvisionDetails{
				RawParameters: []byte(`{"domain": "domain.gov", "headers": ["User-Agent"]}`),
			}
			_, err := broker.Provision(ctx, "123", details, true)

			Expect(err).NotTo(HaveOccurred())
		})

		It("successfully provisions when forwarding all headers using wildcard", func() {
			expectedHeaders := utils.Headers{"*": true}
			route := &models.Route{State: models.Provisioning}
			manager.On("Create", "123", "domain.gov", "origin.cloud.gov", "", false, expectedHeaders, true,
				map[string]string{"Organization": "", "Space": "", "Service": "", "Plan": ""}).Return(route, nil)
			details := brokerapi.ProvisionDetails{
				RawParameters: []byte(`{"domain": "domain.gov", "headers": ["*"]}`),
			}
			_, err := broker.Provision(ctx, "123", details, true)

			Expect(err).NotTo(HaveOccurred())
		})

		It("successfully provisions when forwarding nine headers", func() {
			expectedHeaders := utils.Headers{"One": true, "Two": true, "Three": true, "Four": true, "Five": true, "Six": true, "Seven": true, "Eight": true, "Nine": true, "Host": true}
			route := &models.Route{State: models.Provisioning}
			manager.On("Create", "123", "domain.gov", "origin.cloud.gov", "", false, expectedHeaders, true,
				map[string]string{"Organization": "", "Space": "", "Service": "", "Plan": ""}).Return(route, nil)
			details := brokerapi.ProvisionDetails{
				RawParameters: []byte(`{"domain": "domain.gov", "headers": ["One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"]}`),
			}
			_, err := broker.Provision(ctx, "123", details, true)

			Expect(err).NotTo(HaveOccurred())
		})

		It("returns an error when given duplicate headers", func() {
			expectedHeaders := utils.Headers{"User-Agent": true, "Host": true}
			manager.On("Create", "123", "domain.gov", "origin.cloud.gov", "", false, expectedHeaders, true,
				map[string]string{"Organization": "", "Space": "", "Service": "", "Plan": ""}).Return(nil, errors.New("fail"))
			details := brokerapi.ProvisionDetails{
				RawParameters: []byte(`{"domain": "domain.gov", "headers": ["User-Agent", "Host", "User-Agent"]}`),
			}
			_, err := broker.Provision(ctx, "123", details, true)

			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("must not pass duplicated header 'User-Agent'")))
		})

		It("returns an error when given wildcard and normal headers", func() {
			expectedHeaders := utils.Headers{"*": true}
			manager.On("Create", "123", "domain.gov", "origin.cloud.gov", "", false, expectedHeaders, true,
				map[string]string{"Organization": "", "Space": "", "Service": "", "Plan": ""}).Return(nil, errors.New("fail"))
			details := brokerapi.ProvisionDetails{
				RawParameters: []byte(`{"domain": "domain.gov", "headers": ["*", "User-Agent"]}`),
			}
			_, err := broker.Provision(ctx, "123", details, true)

			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("must not pass whitelisted headers alongside wildcard")))
		})

		It("returns an error when given more than ten headers", func() {
			expectedHeaders := utils.Headers{"One": true, "Two": true, "Three": true, "Four": true, "Five": true, "Six": true, "Seven": true, "Eight": true, "Nine": true, "Ten": true, "Host": true}
			manager.On("Create", "123", "domain.gov", "origin.cloud.gov", "", false, expectedHeaders, true,
				map[string]string{"Organization": "", "Space": "", "Service": "", "Plan": ""}).Return(nil, errors.New("fail"))
			details := brokerapi.ProvisionDetails{
				RawParameters: []byte(`{"domain": "domain.gov", "headers": ["One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten"]}`),
			}
			_, err := broker.Provision(ctx, "123", details, true)

			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("must not set more than 10 headers; got 11")))
		})
	})
})
