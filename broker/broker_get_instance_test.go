package broker_test

import (
	"context"
	"github.com/18F/cf-cdn-service-broker/models"
	"github.com/18F/cf-cdn-service-broker/utils"
	"github.com/pivotal-cf/brokerapi"
	"github.com/stretchr/testify/suite"

	"code.cloudfoundry.org/lager"
	"github.com/18F/cf-cdn-service-broker/broker"
	cfmock "github.com/18F/cf-cdn-service-broker/cf/mocks"
	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/models/mocks"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type GetInstanceSuite struct {
	suite.Suite
	Manager  mocks.RouteManagerIface
	Broker   *broker.CdnServiceBroker
	cfclient cfmock.Client
	settings config.Settings
	logger   lager.Logger
	ctx      context.Context
}

var _ = Describe("GetInstance", func() {

	var s *GetInstanceSuite = &GetInstanceSuite{}

	BeforeEach(func() {
		s.Manager = mocks.RouteManagerIface{}
		s.cfclient = cfmock.Client{}
		s.logger = lager.NewLogger("test")
		s.settings = config.Settings{
			DefaultOrigin:     "origin.cloudapps.digital",
			DefaultDefaultTTL: int64(0),
		}
		s.Broker = broker.New(
			&s.Manager,
			&s.cfclient,
			s.settings,
			s.logger,
		)
		s.ctx = context.Background()
	})

	It("should error when the instance can't be found", func() {
		instanceId := "some-instance-id"
		s.Manager.On("Get", instanceId).
			Return(nil, brokerapi.ErrInstanceDoesNotExist)

		_, err := s.Broker.GetInstance(s.ctx, instanceId)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(brokerapi.ErrInstanceDoesNotExist))
	})

	Describe("when the instance is found", func(){
		var route *models.Route
		var instanceId = "instance-id"

		BeforeEach(func(){
			route = &models.Route{
				InstanceId:                instanceId,
				State:                     models.Provisioning,
				DomainExternal:            "domain1.cloudapps.digital,domain2.cloudapps.digital",
				DomainInternal:            "xyz.cloudfront.net",
				DistId:                    "",
				Origin:                    "",
				Path:                      "",
				InsecureOrigin:            false,
				Certificate:               models.Certificate{},
				UserData:                  models.UserData{},
				UserDataID:                0,
				User:                      utils.User{},
				DefaultTTL:                0,
				ProvisioningSince:         nil,
				IsCertificateManagedByACM: false,
				Certificates:              nil,
			}
			s.Manager.On("Get", instanceId).Return(route, nil)
		})

		It("should return the CloudFront domain in the instance parameters", func(){
			instance, err := s.Broker.GetInstance(s.ctx, instanceId)
			Expect(err).ToNot(HaveOccurred())


			Expect(instance.Parameters).ToNot(BeNil())
			params := instanceParamsToMap(instance.Parameters)
			Expect(params).To(HaveKeyWithValue("cloudfront_domain", route.DomainInternal))
		})
	})
})

func instanceParamsToMap(params interface{}) map[string]string {
	return params.(map[string]string)
}
