package broker_test

import (
	"code.cloudfoundry.org/lager"
	"context"
	"github.com/18F/cf-cdn-service-broker/broker"
	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/models"
	"github.com/18F/cf-cdn-service-broker/models/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-cf/brokerapi/domain/apiresponses"

	cfmock "github.com/18F/cf-cdn-service-broker/cf/mocks"
)

var _ = Describe("GetInstance", func() {
	var (
		routeManagerFake mocks.RouteManagerIface
		logger lager.Logger

		brokerInstance *broker.CdnServiceBroker
	)

	BeforeEach(func() {
		routeManagerFake = mocks.RouteManagerIface{}

		logger = lager.NewLogger("get-instance")
		logger.RegisterSink(lager.NewWriterSink(GinkgoWriter, lager.INFO))

		brokerInstance = broker.New(
			&routeManagerFake,
			&cfmock.Client{},
			config.Settings{},
			logger,
		)

	})
	It("returns a not found error if the instance is not found", func() {
		routeManagerFake.
			On("Get", "instance-id").
			Return(nil, apiresponses.ErrInstanceDoesNotExist)

		_, err := brokerInstance.GetInstance(context.Background(), "instance-id")

		Expect(err).To(Equal(apiresponses.ErrInstanceDoesNotExist))
	})

	Context("when route is provisioned", func(){
		It("outputs the provisioned domains", func() {
			route := models.Route{
				DomainExternal: "domain1.paas,domain2.paas,domain3.paas",
				DomainInternal: "something.cloudfront.net",
			}

			routeManagerFake.
				On("Get", "instance-id").
				Return(&route, nil)

			result, err := brokerInstance.GetInstance(context.Background(), "instance-id")

			Expect(err).ToNot(HaveOccurred())
			params := result.Parameters.(map[string]string)
			Expect(params["domains"]).To(Equal(route.DomainExternal))
			Expect(params["cloudfront_domain"]).To(Equal(route.DomainInternal))
		})
	})
})
