package getter_test

import (
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Opcode", func() {
	Context("GetOpcodeString", func() {
		var (
			s       string
			strFunc = getter.NewDnsMsgStrFunc("Opcode")
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
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Opcode: 15}}
				s = strFunc(m)
			})
			It("returns OPCODE*", func() {
				Expect(s).To(Equal("OPCODE15"))
			})
		})
		When("opcode is known", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeNotify}}
				s = strFunc(m)
			})
			It("returns NOTIFY", func() {
				Expect(s).To(Equal("NOTIFY"))
			})
		})
	})
	Context("GetOpcode", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnsMsgGetFunc("Opcode")
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
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeNotify}}
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(dns.OpcodeNotify))
			})
		})
	})
})
