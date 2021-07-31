package testtool_test

import (
	"testing"

	"github.com/miekg/dns"
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
	Context("MustNewZone", func() {
		When("input is invalid", func() {
			It("raises panic", func() {
				Expect(func() { MustNewZone("..", dns.ClassCSNET) }).Should(Panic())
			})
		})
		When("input is valid", func() {
			It("returns zone", func() {
				Expect(MustNewZone("example.jp.", dns.ClassINET)).NotTo(BeNil())
			})
		})
	})
	Context("MustNewNameNode", func() {
		When("input is invalid", func() {
			It("raises panic", func() {
				Expect(func() { MustNewNameNode("..", dns.ClassCSNET) }).Should(Panic())
			})
		})
		When("input is valid", func() {
			It("returns zone", func() {
				Expect(MustNewNameNode("example.jp.", dns.ClassINET)).NotTo(BeNil())
			})
		})
	})
	Context("MustNewRRSet", func() {
		When("input is invalid", func() {
			It("raises panic", func() {
				Expect(func() { MustNewRRSet("..", 300, dns.ClassINET, dns.TypeA, nil) }).Should(Panic())
			})
		})
		When("input is valid", func() {
			It("returns zone", func() {
				Expect(MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, nil)).NotTo(BeNil())
			})
		})
	})
})
