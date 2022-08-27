package getter_test

import (
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RecursionDesired", func() {
	Context("GetRecursionDesiredString", func() {
		var (
			s       string
			strFunc = getter.NewDnsMsgStrFunc("RD")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = strFunc(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("ad bit is on", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: true}}
				s = strFunc(m)
			})
			It("returns on", func() {
				Expect(s).To(Equal(getter.MatchStringOn))
			})
		})
		When("ad bit is off", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: false}}
				s = strFunc(m)
			})
			It("returns off", func() {
				Expect(s).To(Equal(getter.MatchStringOff))
			})
		})
	})
	Context("GetRecursionDesired", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnsMsgGetFunc("RecursionDesired")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getFunc(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("ad bit is on", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: true}}
				s = getFunc(m)
			})
			It("returns true", func() {
				Expect(s).To(BeTrue())
			})
		})
		When("ad bit is off", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: false}}
				s = getFunc(m)
			})
			It("returns false", func() {
				Expect(s).To(BeFalse())
			})
		})
	})
})
