package models

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Route", func() {
	Context("GetDomains", func() {
		It("Returns zero domains", func() {
			route := Route{DomainExternal: ""}

			Expect(route.GetDomains()).To(Equal([]string{}))
		})
		It("Returns a single domain", func() {
			route := Route{DomainExternal: "www.foo.com"}

			Expect(route.GetDomains()).To(Equal([]string{
				"www.foo.com",
			}))
		})

		It("Returns two domains", func() {
			route := Route{DomainExternal: "www.foo.com,www.foo.net"}

			Expect(route.GetDomains()).To(Equal([]string{
				"www.foo.com",
				"www.foo.net",
			}))
		})

		It("Returns two domains even with misplaced commas", func() {
			route := Route{DomainExternal: ",www.foo.com,,www.foo.net,"}

			Expect(route.GetDomains()).To(Equal([]string{
				"www.foo.com",
				"www.foo.net",
			}))
		})
	})
})
