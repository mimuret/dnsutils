package testtool_test

import (
	"testing"

	. "github.com/mimuret/dnsutils/testtool"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestDNSUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "testtool Suite")
}

var _ = Describe("testtool", func() {
	Context("MustNewRR", func() {
		When("input is invalid", func() {
			It("raises panic", func() {
				Expect(func() { MustNewRR("example.jp.") }).Should(Panic())
			})
		})
		When("input is valid", func() {
			It("returns rr", func() {
				Expect(MustNewRR("example.jp. 300 IN A 192.168.0.1")).NotTo(BeNil())
			})
		})
	})
})
