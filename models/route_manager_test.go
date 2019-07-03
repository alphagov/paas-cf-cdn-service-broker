package models

import (
	"bytes"
	"errors"
	"strings"

	"time"

	"code.cloudfoundry.org/lager"
	"github.com/jinzhu/gorm"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/pki"
	"github.com/18F/cf-cdn-service-broker/utils"

	"github.com/stretchr/testify/mock"

	. "github.com/onsi/ginkgo"
)

var _ = Describe("RouteManager", func() {
	It("delete orphaned certs", func() {

		logger := lager.NewLogger("cdn-cron-test")
		logOutput := bytes.NewBuffer([]byte{})
		logger.RegisterSink(lager.NewWriterSink(logOutput, lager.ERROR))

		settings, _ := config.NewSettings()
		session := session.New(nil)

		fakeiam := iam.New(session)
		fakeiam.Handlers.Clear()
		fakeiam.Handlers.Send.PushBack(func(r *request.Request) {

			switch r.Operation.Name {
			case "ListServerCertificates":
				old := time.Now().AddDate(0, 0, -2)
				current := time.Now().AddDate(0, 0, 0)

				list := []*iam.ServerCertificateMetadata{
					&iam.ServerCertificateMetadata{
						Arn:                   aws.String("an-active-certificate"),
						ServerCertificateName: aws.String("an-active-certificate"),
						ServerCertificateId:   aws.String("an-active-certificate"),
						UploadDate:            &old,
					},
					&iam.ServerCertificateMetadata{
						Arn:                   aws.String("some-other-active-certificate"),
						ServerCertificateName: aws.String("some-other-active-certificate"),
						ServerCertificateId:   aws.String("some-other-active-certificate"),
						UploadDate:            &old,
					},
					&iam.ServerCertificateMetadata{
						Arn:                   aws.String("orphaned-but-not-old-enough"),
						ServerCertificateName: aws.String("orphaned-but-not-old-enough"),
						ServerCertificateId:   aws.String("this-cert-should-not-be-deleted"),
						UploadDate:            &current,
					},
					&iam.ServerCertificateMetadata{
						Arn:                   aws.String("some-orphaned-cert"),
						ServerCertificateName: aws.String("some-orphaned-cert"),
						ServerCertificateId:   aws.String("this-cert-should-be-deleted"),
						UploadDate:            &old,
					},
					&iam.ServerCertificateMetadata{
						Arn:                   aws.String("some-other-orphaned-cert"),
						ServerCertificateName: aws.String("some-other-orphaned-cert"),
						ServerCertificateId:   aws.String("this-cert-should-also-be-deleted"),
						UploadDate:            &old,
					},
				}
				data := r.Data.(*iam.ListServerCertificatesOutput)
				data.IsTruncated = aws.Bool(false)
				data.ServerCertificateMetadataList = list
			}
		})

		fakecf := cloudfront.New(session)
		fakecf.Handlers.Clear()
		fakecf.Handlers.Send.PushBack(func(r *request.Request) {

			switch r.Operation.Name {
			case "ListDistributions2016_11_25":
				list := []*cloudfront.DistributionSummary{
					&cloudfront.DistributionSummary{
						ARN: aws.String("some-distribution"),
						ViewerCertificate: &cloudfront.ViewerCertificate{
							IAMCertificateId: aws.String("an-active-certificate"),
						},
					},
					&cloudfront.DistributionSummary{
						ARN: aws.String("some-other-distribution"),
						ViewerCertificate: &cloudfront.ViewerCertificate{
							IAMCertificateId: aws.String("some-other-active-certificate"),
						},
					},
				}

				data := r.Data.(*cloudfront.ListDistributionsOutput)
				data.DistributionList = &cloudfront.DistributionList{
					IsTruncated: aws.Bool(false),
					Items:       list,
				}
			}
		})

		mui := new(MockUtilsIam)
		mui.Settings = settings
		mui.Service = fakeiam

		mui.On("DeleteCertificate", "some-orphaned-cert").Return(nil)
		mui.On("DeleteCertificate", "some-other-orphaned-cert").Return(nil)

		m := NewManager(
			logger,
			mui,
			&utils.Distribution{settings, fakecf},
			settings,
			&gorm.DB{},
		)

		m.DeleteOrphanedCerts()

		mui.AssertExpectations(GinkgoT())
	})
	It("delete orphaned certs delete fails", func() {

		logger := lager.NewLogger("cdn-cron-test")
		logOutput := bytes.NewBuffer([]byte{})
		logger.RegisterSink(lager.NewWriterSink(logOutput, lager.ERROR))

		settings, _ := config.NewSettings()
		session := session.New(nil)

		fakeiam := iam.New(session)
		fakeiam.Handlers.Clear()
		fakeiam.Handlers.Send.PushBack(func(r *request.Request) {

			switch r.Operation.Name {
			case "ListServerCertificates":
				old := time.Now().AddDate(0, 0, -2)

				list := []*iam.ServerCertificateMetadata{
					&iam.ServerCertificateMetadata{
						Arn:                   aws.String("some-orphaned-cert"),
						ServerCertificateName: aws.String("some-orphaned-cert"),
						ServerCertificateId:   aws.String("this-cert-should-be-deleted"),
						UploadDate:            &old,
					},
				}
				data := r.Data.(*iam.ListServerCertificatesOutput)
				data.IsTruncated = aws.Bool(false)
				data.ServerCertificateMetadataList = list
			}
		})

		fakecf := cloudfront.New(session)
		fakecf.Handlers.Clear()
		fakecf.Handlers.Send.PushBack(func(r *request.Request) {

			switch r.Operation.Name {
			case "ListDistributions2016_11_25":
				list := []*cloudfront.DistributionSummary{}
				data := r.Data.(*cloudfront.ListDistributionsOutput)
				data.DistributionList = &cloudfront.DistributionList{
					IsTruncated: aws.Bool(false),
					Items:       list,
				}
			}
		})

		mui := new(MockUtilsIam)
		mui.Settings = settings
		mui.Service = fakeiam

		mui.On("DeleteCertificate", "some-orphaned-cert").Return(errors.New("DeleteCertificate error"))

		m := NewManager(
			logger,
			mui,
			&utils.Distribution{settings, fakecf},
			settings,
			&gorm.DB{},
		)

		m.DeleteOrphanedCerts()

		mui.AssertExpectations(GinkgoT())

		if !strings.Contains(logOutput.String(), "DeleteCertificate error") {
			GinkgoT().Errorf("was expecting DeleteCertificate error to be logged")
		}
	})
	It("delete orphaned certs when listing certificates fail", func() {

		logger := lager.NewLogger("cdn-cron-test")
		logOutput := bytes.NewBuffer([]byte{})
		logger.RegisterSink(lager.NewWriterSink(logOutput, lager.ERROR))

		settings, _ := config.NewSettings()
		session := session.New(nil)

		fakecf := cloudfront.New(session)
		fakecf.Handlers.Clear()
		fakecf.Handlers.Send.PushBack(func(r *request.Request) {

			switch r.Operation.Name {
			case "ListDistributions2016_11_25":
				list := []*cloudfront.DistributionSummary{
					&cloudfront.DistributionSummary{
						ARN: aws.String("some-distribution"),
						ViewerCertificate: &cloudfront.ViewerCertificate{
							IAMCertificateId: aws.String("an-active-certificate"),
						},
					},
					&cloudfront.DistributionSummary{
						ARN: aws.String("some-other-distribution"),
						ViewerCertificate: &cloudfront.ViewerCertificate{
							IAMCertificateId: aws.String("some-other-active-certificate"),
						},
					},
				}

				data := r.Data.(*cloudfront.ListDistributionsOutput)
				data.DistributionList = &cloudfront.DistributionList{
					IsTruncated: aws.Bool(false),
					Items:       list,
				}
			}
		})

		fakeiam := iam.New(session)
		fakeiam.Handlers.Clear()
		fakeiam.Handlers.Send.PushBack(func(r *request.Request) {
			r.Data = nil
			r.Error = errors.New("ListServerCertificates error")
		})

		mui := new(MockUtilsIam)
		mui.Settings = settings
		mui.Service = fakeiam

		m := NewManager(
			logger,
			mui,
			&utils.Distribution{settings, fakecf},
			settings,
			&gorm.DB{},
		)

		m.DeleteOrphanedCerts()

		mui.AssertNumberOfCalls(GinkgoT(), "DeleteCertificate", 0)
		mui.AssertExpectations(GinkgoT())

		if !strings.Contains(logOutput.String(), "ListServerCertificates error") {
			GinkgoT().Errorf("was expecting ListServerCertificates error to be logged")
		}
	})
	It("delete orphaned certs when listing cloud front dists fail", func() {

		logger := lager.NewLogger("cdn-cron-test")
		logOutput := bytes.NewBuffer([]byte{})
		logger.RegisterSink(lager.NewWriterSink(logOutput, lager.ERROR))

		settings, _ := config.NewSettings()
		session := session.New(nil)

		fakecf := cloudfront.New(session)
		fakecf.Handlers.Clear()
		fakecf.Handlers.Send.PushBack(func(r *request.Request) {
			r.Data = nil
			r.Error = errors.New("ListDistributions error")
		})

		fakeiam := iam.New(session)
		fakeiam.Handlers.Clear()
		fakeiam.Handlers.Send.PushBack(func(r *request.Request) {

			switch r.Operation.Name {
			case "ListServerCertificates":
				old := time.Now().AddDate(0, 0, -2)

				list := []*iam.ServerCertificateMetadata{
					&iam.ServerCertificateMetadata{
						Arn:                   aws.String("some-orphaned-cert"),
						ServerCertificateName: aws.String("some-orphaned-cert"),
						ServerCertificateId:   aws.String("this-cert-should-be-deleted"),
						UploadDate:            &old,
					},
				}
				data := r.Data.(*iam.ListServerCertificatesOutput)
				data.IsTruncated = aws.Bool(false)
				data.ServerCertificateMetadataList = list
			}
		})

		mui := new(MockUtilsIam)
		mui.Settings = settings
		mui.Service = fakeiam

		m := NewManager(
			logger,
			mui,
			&utils.Distribution{settings, fakecf},
			settings,
			&gorm.DB{},
		)

		m.DeleteOrphanedCerts()

		mui.AssertNumberOfCalls(GinkgoT(), "DeleteCertificate", 0)
		mui.AssertExpectations(GinkgoT())

		if !strings.Contains(logOutput.String(), "ListDistributions error") {
			GinkgoT().Errorf("was expecting ListDistributions error to be logged")
		}
	})
})

type MockUtilsIam struct {
	mock.Mock

	Settings config.Settings
	Service  *iam.IAM
}

func (_f MockUtilsIam) UploadCertificate(name string, pair pki.KeyPair) (string, error) {
	return "", nil
}

func (_f MockUtilsIam) ListCertificates(callback func(iam.ServerCertificateMetadata) bool) error {
	orig := &utils.Iam{Settings: _f.Settings, Service: _f.Service}
	return orig.ListCertificates(callback)
}

func (_f MockUtilsIam) DeleteCertificate(certName string) error {
	args := _f.Called(certName)
	return args.Error(0)
}
