package getter_test

import (
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CanonicalQName", func() {
	Context("GetCanonicalQNameString", func() {
		var (
			s string
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getter.GetCanonicalQNameString(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("question is nil", func() {
			BeforeEach(func() {
				s = getter.GetCanonicalQNameString(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid msg", func() {
			BeforeEach(func() {
				m := &dns.Msg{Question: []dns.Question{{Name: "WwW.example.jp"}}}
				s = getter.GetCanonicalQNameString(m)
			})
			It("returns qname", func() {
				Expect(s).To(Equal("www.example.jp."))
			})
		})
	})
	Context("GetCanonicalQName", func() {
		var (
			s interface{}
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getter.GetCanonicalQName(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("question is nil", func() {
			BeforeEach(func() {
				s = getter.GetCanonicalQName(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(BeNil())
			})
		})
		When("msg is not nil", func() {
			BeforeEach(func() {
				m := &dns.Msg{Question: []dns.Question{{Name: "WwW.example.jp"}}}
				s = getter.GetCanonicalQName(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal("www.example.jp."))
			})
		})
	})
})
