package testtool_test

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
	. "github.com/mimuret/dnsutils/testtool"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TestGenerator", func() {
	var (
		err error
		g   *TestGenerator
	)
	BeforeEach(func() {
		g = &TestGenerator{Generator: &dnsutils.DefaultGenerator{}}
	})
	Context("NewNameNode", func() {
		When("not exist NewNewNameNodeErr", func() {
			BeforeEach(func() {
				_, err = g.NewNameNode("example.jp", dns.ClassINET)
			})
			It("successful", func() {
				Expect(err).To(Succeed())
			})
		})
		When("exist NewNewNameNodeErr", func() {
			BeforeEach(func() {
				g.NewNewNameNodeErr = fmt.Errorf("error")
				_, err = g.NewNameNode("example.jp", dns.ClassINET)
			})
			It("returns err", func() {
				Expect(err).To(Equal(g.NewNewNameNodeErr))
			})
		})
	})
	Context("NewRRSet", func() {
		When("not exist NewRRSetErr", func() {
			BeforeEach(func() {
				_, err = g.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA)
			})
			It("successful", func() {
				Expect(err).To(Succeed())
			})
		})
		When("exist NewRRSetErr", func() {
			BeforeEach(func() {
				g.NewRRSetErr = fmt.Errorf("error")
				_, err = g.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA)
			})
			It("returns err", func() {
				Expect(err).To(Equal(g.NewRRSetErr))
			})
		})
	})
})
