package dnsutils_test

import (
	"bytes"
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/example.jp.normal
var testZoneNormal []byte

//go:embed testdata/example.jp.error
var testZoneError []byte

var _ = Describe("Zone", func() {
	Context("Test for GetName", func() {
		It("returns canonical zone name", func() {
			z := dnsutils.NewZone("example.jp", dns.ClassINET)
			Expect(z.GetName()).To(Equal("example.jp."))
		})
	})
	Context("Test for GetRootNode", func() {
		It("returns root NameNode", func() {
			z := dnsutils.NewZone("example.jp", dns.ClassINET)
			Expect(z.GetRootNode()).NotTo(BeNil())
			Expect(z.GetRootNode().GetName()).To(Equal("example.jp."))
		})
	})
	Context("Test for Read", func() {
		It("can read data", func() {
			testZoneNormalBuf := bytes.NewBuffer(testZoneNormal)
			z := dnsutils.NewZone("example.jp", dns.ClassINET)
			err := z.Read(testZoneNormalBuf)
			Expect(err).To(BeNil())
			nn, ok := z.GetRootNode().GetNameNode("test.hoge.example.jp")
			Expect(ok).To(BeTrue())
			Expect(nn.GetName()).To(Equal("test.hoge.example.jp."))
			set := nn.GetRRSet(dns.TypeA)
			Expect(set).NotTo(BeNil())
			Expect(set.GetRRtype()).To(Equal(dns.TypeA))
			Expect(set.GetRRs()).To(Equal([]dns.RR{
				MustNewRR("test.hoge.example.jp. 3600 IN A 192.168.2.1"),
				MustNewRR("test.hoge.example.jp. 3600 IN A 192.168.2.2"),
			}))
		})
		It("can't read not valid data", func() {
			testZoneErrorBuf := bytes.NewBuffer(testZoneError)
			z := dnsutils.NewZone("example.jp", dns.ClassINET)
			err := z.Read(testZoneErrorBuf)
			Expect(err).NotTo(BeNil())
		})
	})
})
