package getter_test

import (
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QClass", func() {
	Context("GetQClassString", func() {
		var (
			s       string
			strFunc = getter.NewDnsMsgStrFunc("QClass")
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
				m := &dns.Msg{Question: []dns.Question{
					{Qclass: 253},
				}}
				s = strFunc(m)
			})
			It("returns CLASS*", func() {
				Expect(s).To(Equal("CLASS253"))
			})
		})
		When("opcode is known", func() {
			BeforeEach(func() {
				m := &dns.Msg{Question: []dns.Question{
					{Qclass: dns.ClassANY},
				}}
				s = strFunc(m)
			})
			It("returns ANY", func() {
				Expect(s).To(Equal("ANY"))
			})
		})
	})
	Context("GetQClass", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnsMsgGetFunc("QClass")
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
				m := &dns.Msg{Question: []dns.Question{
					{Qclass: 253},
				}}
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(uint16(253)))
			})
		})
	})
})
