package broker

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-cf/brokerapi"
)

var _ = Describe("Bind", func() {
	It("returns an error when attempting to bind", func() {
		b := CdnServiceBroker{}
		_, err := b.Bind(context.Background(), "", "", brokerapi.BindDetails{})
		Expect(err).To(HaveOccurred())
	})

	It("returns an error when attempting to unbind", func() {
		b := CdnServiceBroker{}
		err := b.Unbind(context.Background(), "", "", brokerapi.UnbindDetails{})
		Expect(err).To(HaveOccurred())
	})
})
