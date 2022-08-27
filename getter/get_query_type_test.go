package getter_test

import (
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QType", func() {
	Context("GetQTypeString", func() {
		var (
			s       string
			strFunc = getter.NewDnsMsgStrFunc("QType")
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
		When("opcode is unknown", func() {
			BeforeEach(func() {
				m := &dns.Msg{Question: []dns.Question{{Qtype: 65534}}}
				s = strFunc(m)
			})
			It("returns TYPE*", func() {
				Expect(s).To(Equal("TYPE65534"))
			})
		})
		When("opcode is known", func() {
			BeforeEach(func() {
				m := &dns.Msg{Question: []dns.Question{{Qtype: dns.TypeHTTPS}}}
				s = strFunc(m)
			})
			It("returns HTTPS", func() {
				Expect(s).To(Equal("HTTPS"))
			})
		})
	})
	Context("GetQType", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnsMsgGetFunc("QType")
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
				m := &dns.Msg{Question: []dns.Question{{Qtype: 65534}}}
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(uint16(65534)))
			})
		})
	})
})
