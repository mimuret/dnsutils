package getter_test

import (
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QName", func() {
	Context("GetQNameString", func() {
		var (
			s string
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getter.GetQNameString(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("question is nil", func() {
			BeforeEach(func() {
				s = getter.GetQNameString(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid msg", func() {
			BeforeEach(func() {
				m := &dns.Msg{Question: []dns.Question{{Name: "WwW.example.jp"}}}
				s = getter.GetQNameString(m)
			})
			It("returns qname", func() {
				Expect(s).To(Equal("WwW.example.jp"))
			})
		})
	})
	Context("GetQName", func() {
		var (
			s interface{}
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getter.GetQName(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("question is nil", func() {
			BeforeEach(func() {
				s = getter.GetQName(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(BeNil())
			})
		})
		When("msg is not nil", func() {
			BeforeEach(func() {
				m := &dns.Msg{Question: []dns.Question{{Name: "WwW.example.jp"}}}
				s = getter.GetQName(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal("WwW.example.jp"))
			})
		})
	})
})
