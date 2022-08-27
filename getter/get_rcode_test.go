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
			s       string
			strFunc = getter.NewDnsMsgStrFunc("Rcode")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = strFunc(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("opcode is unknown", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: 255}}
				s = strFunc(m)
			})
			It("returns OPCODE*", func() {
				Expect(s).To(Equal("RCODE255"))
			})
		})
		When("opcode is known", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}
				s = strFunc(m)
			})
			It("returns SERVFAIL", func() {
				Expect(s).To(Equal("SERVFAIL"))
			})
		})
	})
	Context("GetRcode", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnsMsgGetFunc("Rcode")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getFunc(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("msg is not nil", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(dns.RcodeServerFailure))
			})
		})
	})
})
