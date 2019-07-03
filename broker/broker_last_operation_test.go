package broker

import (
	"context"
	"errors"

	"code.cloudfoundry.org/lager"
	"github.com/pivotal-cf/brokerapi"

	cfmock "github.com/18F/cf-cdn-service-broker/cf/mocks"
	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/models"
	"github.com/18F/cf-cdn-service-broker/models/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("LastOperation", func() {
	var (
		manager  mocks.RouteManagerIface
		cfclient cfmock.Client
		settings config.Settings
		logger   lager.Logger
		ctx      context.Context
	)

	BeforeEach(func() {
		manager = mocks.RouteManagerIface{}
		cfclient = cfmock.Client{}
		ctx = context.Background()
	})

	It("returns an error when there is no service instance", func() {
		manager.On("Get", "").Return(&models.Route{}, errors.New("not found"))
		b := New(&manager, &cfclient, settings, logger)
		operation, err := b.LastOperation(ctx, "", "")

		Expect(operation.State).To(Equal(brokerapi.Failed))
		Expect(operation.Description).To(Equal("Service instance not found"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("returns last operation succeeded", func() {
		manager := mocks.RouteManagerIface{}
		route := &models.Route{
			State:          models.Provisioned,
			DomainExternal: "cdn.cloud.gov", DomainInternal: "abc.cloudfront.net",
			Origin: "cdn.apps.cloud.gov",
		}
		manager.On("Get", "123").Return(route, nil)
		manager.On("Poll", route).Return(nil)
		b := New(&manager, &cfclient, settings, logger)
		operation, err := b.LastOperation(ctx, "123", "")

		Expect(operation.State).To(Equal(brokerapi.Succeeded))
		Expect(operation.Description).To(Equal("Service instance provisioned [cdn.cloud.gov => cdn.apps.cloud.gov]; CDN domain abc.cloudfront.net"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("returns last operation provsioning", func() {
		route := &models.Route{
			State:          models.Provisioning,
			DomainExternal: "cdn.cloud.gov",
			Origin:         "cdn.apps.cloud.gov",
			ChallengeJSON:  []byte("[]"),
		}
		manager.On("Get", "123").Return(route, nil)
		manager.On("GetDNSInstructions", route).Return([]string{"token"}, nil)
		manager.On("Poll", route).Return(nil)
		b := New(&manager, &cfclient, settings, logger)
		operation, err := b.LastOperation(ctx, "123", "")

		Expect(operation.State).To(Equal(brokerapi.InProgress))
		Expect(operation.Description).To(ContainSubstring("Provisioning in progress [cdn.cloud.gov => cdn.apps.cloud.gov]"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("returns last operation deprovisioning", func() {
		route := &models.Route{
			State:          models.Deprovisioning,
			DomainExternal: "cdn.cloud.gov",
			DomainInternal: "abc.cloudfront.net",
			Origin:         "cdn.apps.cloud.gov",
		}
		manager.On("Get", "123").Return(route, nil)
		manager.On("Poll", route).Return(nil)
		b := New(&manager, &cfclient, settings, logger)
		operation, err := b.LastOperation(ctx, "123", "")

		Expect(operation.State).To(Equal(brokerapi.InProgress))
		Expect(operation.Description).To(ContainSubstring("Deprovisioning in progress [cdn.cloud.gov => cdn.apps.cloud.gov]; CDN domain abc.cloudfront.net"))
		Expect(err).NotTo(HaveOccurred())
	})
})
