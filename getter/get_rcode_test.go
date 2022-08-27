package getter_test

import (
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Rcode", func() {
	Context("GetRcodeString", func() {
		var (
			s string
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getter.GetRcodeString(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("opcode is unknown", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: 255}}
				s = getter.GetRcodeString(m)
			})
			It("returns OPCODE*", func() {
				Expect(s).To(Equal("RCODE255"))
			})
		})
		When("opcode is known", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}
				s = getter.GetRcodeString(m)
			})
			It("returns SERVFAIL", func() {
				Expect(s).To(Equal("SERVFAIL"))
			})
		})
	})
	Context("GetRcode", func() {
		var (
			s interface{}
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getter.GetRcode(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("msg is not nil", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}
				s = getter.GetRcode(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(dns.RcodeServerFailure))
			})
		})
	})
})
