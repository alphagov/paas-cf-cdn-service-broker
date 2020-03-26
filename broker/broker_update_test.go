package broker_test

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/stretchr/testify/suite"

	"code.cloudfoundry.org/lager"
	"github.com/pivotal-cf/brokerapi"

	"github.com/18F/cf-cdn-service-broker/broker"
	cfmock "github.com/18F/cf-cdn-service-broker/cf/mocks"
	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/models/mocks"
	"github.com/18F/cf-cdn-service-broker/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type UpdateSuite struct {
	suite.Suite
	Manager  mocks.RouteManagerIface
	Broker   *broker.CdnServiceBroker
	cfclient cfmock.Client
	settings config.Settings
	logger   lager.Logger
	ctx      context.Context
}

func (s *UpdateSuite) allowUpdateWithExpectedHeaders(expectedHeaders utils.Headers) {
	s.Manager.On("Update", "", "domain.gov", "origin.cloud.gov", ".", s.settings.DefaultDefaultTTL, true, expectedHeaders, true).Return(nil)
}

func (s *UpdateSuite) failOnUpdateWithExpectedHeaders(expectedHeaders utils.Headers) {
	s.Manager.On("Update", "", "domain.gov", "origin.cloud.gov", ".", s.settings.DefaultDefaultTTL, true, expectedHeaders, true).Return(errors.New("fail"))
}

var _ = Describe("Update", func() {
	var s *UpdateSuite = &UpdateSuite{}

	BeforeEach(func() {
		s.Manager = mocks.RouteManagerIface{}
		s.cfclient = cfmock.Client{}
		s.logger = lager.NewLogger("test")
		s.settings = config.Settings{
			DefaultOrigin:     "origin.cloud.gov",
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

	It("should error due to lack of update support", func() {
		details := brokerapi.UpdateDetails{
			RawParameters: json.RawMessage(`{"origin": ""}`),
		}
		_, err := s.Broker.Update(s.ctx, "", details, true)

		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("service no longer supports updates. please contact support")))
	})
})
