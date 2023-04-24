package getter_test

import (
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QName", func() {
	Context("GetQNameETLDPlusString", func() {
		var (
			s       string
			strFunc = getter.NewDnsMsgStrFunc("QNameETLDPlus")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = strFunc(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("question is nil", func() {
			BeforeEach(func() {
				s = strFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid msg", func() {
			BeforeEach(func() {
				m := &dns.Msg{Question: []dns.Question{{Name: "WwW.example.jp"}}}
				s = strFunc(m)
			})
			It("returns qname", func() {
				Expect(s).To(Equal("example.jp"))
			})
		})
	})
	Context("QNameETLDPlus", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnsMsgGetFunc("QNameETLDPlus")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getFunc(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("question is nil", func() {
			BeforeEach(func() {
				s = getFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(BeNil())
			})
		})
		When("msg is not nil", func() {
			BeforeEach(func() {
				m := &dns.Msg{Question: []dns.Question{{Name: "WwW.example.jp"}}}
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal("example.jp"))
			})
		})
	})
})
