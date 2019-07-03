package utils

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/pki"
)

type IamIface interface {
	UploadCertificate(name string, pair pki.KeyPair) (string, error)
	DeleteCertificate(name string) error
	ListCertificates(callback func(iam.ServerCertificateMetadata) bool) error
}

type Iam struct {
	Settings config.Settings
	Service  *iam.IAM
}

func (i *Iam) UploadCertificate(name string, pair pki.KeyPair) (string, error) {
	resp, err := i.Service.UploadServerCertificate(&iam.UploadServerCertificateInput{
		CertificateBody:       aws.String(string(pair.Certificate)),
		PrivateKey:            aws.String(string(pair.PrivateKey)),
		ServerCertificateName: aws.String(name),
		Path:                  aws.String(fmt.Sprintf("/cloudfront/%s/", i.Settings.IamPathPrefix)),
	})
	if err != nil {
		return "", err
	}

	return *resp.ServerCertificateMetadata.ServerCertificateId, nil
}

func (i *Iam) ListCertificates(callback func(iam.ServerCertificateMetadata) bool) error {
	params := &iam.ListServerCertificatesInput{
		PathPrefix: aws.String(fmt.Sprintf("/cloudfront/%s/", i.Settings.IamPathPrefix)),
	}

	return i.Service.ListServerCertificatesPages(params,
		func(page *iam.ListServerCertificatesOutput, lastPage bool) bool {
			for _, v := range page.ServerCertificateMetadataList {
				// stop iteration if the callback tells us to
				if callback(*v) == false {
					return false
				}
			}

			return true
		})
}

func (i *Iam) DeleteCertificate(name string) error {
	_, err := i.Service.DeleteServerCertificate(&iam.DeleteServerCertificateInput{
		ServerCertificateName: aws.String(name),
	})

	return err
}
