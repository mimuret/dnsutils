package getter_test

import (
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Authoritative", func() {
	Context("GetAuthoritativeString", func() {
		var (
			s string
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getter.GetAuthoritativeString(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("ad bit is on", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}}
				s = getter.GetAuthoritativeString(m)
			})
			It("returns on", func() {
				Expect(s).To(Equal(getter.MatchStringOn))
			})
		})
		When("ad bit is off", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: false}}
				s = getter.GetAuthoritativeString(m)
			})
			It("returns off", func() {
				Expect(s).To(Equal(getter.MatchStringOff))
			})
		})
	})
	Context("GetAuthoritative", func() {
		var (
			s interface{}
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getter.GetAuthoritative(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("ad bit is on", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}}
				s = getter.GetAuthoritative(m)
			})
			It("returns true", func() {
				Expect(s).To(BeTrue())
			})
		})
		When("ad bit is off", func() {
			BeforeEach(func() {
				m := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: false}}
				s = getter.GetAuthoritative(m)
			})
			It("returns false", func() {
				Expect(s).To(BeFalse())
			})
		})
	})
})
