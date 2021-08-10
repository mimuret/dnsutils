package testtool_test

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
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
	Context("TestGenerator", func() {
		var (
			g   *TestGenerator
			err error
		)
		BeforeEach(func() {
			g = &TestGenerator{Generator: dnsutils.DefaultGenerator{}}
		})
		Context("NewNameNode", func() {
			When("not exist NewNewNameNodeErr", func() {
				BeforeEach(func() {
					_, err = g.NewNameNode("example.jp.", dns.ClassINET)
				})
				It("run Generator func", func() {
					Expect(err).Should(Succeed())
				})
			})
			When("exist NewNewNameNodeErr", func() {
				BeforeEach(func() {
					g.NewNewNameNodeErr = fmt.Errorf("fail NewNewNameNodeErr")
					_, err = g.NewNameNode("example.jp.", dns.ClassINET)
				})
				It("returns NewNewNameNodeErr", func() {
					Expect(err).Should(Equal(g.NewNewNameNodeErr))
				})
			})
		})
		Context("NewRRSet", func() {
			When("not exist NewRRSetErr", func() {
				BeforeEach(func() {
					_, err = g.NewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeTXT)
				})
				It("run Generator func", func() {
					Expect(err).Should(Succeed())
				})
			})
			When("exist NewRRSetErr", func() {
				BeforeEach(func() {
					g.NewRRSetErr = fmt.Errorf("fail NewRRSetErr")
					_, err = g.NewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeTXT)
				})
				It("returns NewRRSetErr", func() {
					Expect(err).Should(Equal(g.NewRRSetErr))
				})
			})
		})
	})
})
