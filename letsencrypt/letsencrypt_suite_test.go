package letsencrypt_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLetsencrypt(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Letsencrypt Suite")
}
