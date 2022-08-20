package matcher_test

import (
	_ "embed"
	"encoding/json"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/dnsmsg_authoritative_fail.json
var matchDNSMsgAuthoritativeFailData []byte

//go:embed testdata/dnsmsg_authoritative_success.json
var matchDNSMsgAuthoritativeValidData []byte

var _ = Describe("Authoritative", func() {
	Context("NewMatchDNSMsgAuthoritative", func() {
		var (
			m   matcher.DnsMsgMatcher
			err error
		)
		When("arg is bool", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgAuthoritative(true)
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("arg is not bool", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgAuthoritative("true")
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
	})
	Context("UnmarshalArg", func() {
		var (
			err error
			mc  *matcher.MatcherConfig
		)
		BeforeEach(func() {
			mc = &matcher.MatcherConfig{}
		})
		When("valid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgAuthoritativeValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "AA",
					Type: matcher.MatcherTypeDnsMsg,
					Arg:  true,
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgAuthoritativeFailData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
	})
	Context("BuildDnsMsgMatcher", func() {
		var (
			err error
			m1  matcher.DnsMsgMatcher
			m2  matcher.DnsMsgMatcher
		)
		BeforeEach(func() {
			m1, err = matcher.NewMatchDNSMsgAuthoritative(true)
			Expect(err).To(Succeed())
		})
		When("Name is Authoritative", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "Authoritative",
					Arg:  true,
				})
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m2).To(Equal(m1))
			})
		})
		When("Name is AA", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "AA",
					Arg:  true,
				})
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m2).To(Equal(m1))
			})
		})
	})
	Context("Match", func() {
		var (
			err error
			m   matcher.DnsMsgMatcher
		)
		When("match true", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgAuthoritative(true)
				Expect(err).To(Succeed())
			})
			When("msg.Authoritative = true", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}})).To(BeTrue())
				})
			})
			When("msg.Authoritative = false", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: false}})).To(BeFalse())
				})
			})
		})
		When("match false", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgAuthoritative(false)
				Expect(err).To(Succeed())
			})
			When("msg.Authoritative = true", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}})).To(BeFalse())
				})
			})
			When("msg.Authoritative = false", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: false}})).To(BeTrue())
				})
			})
		})
	})
})
