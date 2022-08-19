package matcher_test

import (
	_ "embed"
	"encoding/json"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/dnsmsg_recursion_desired_fail.json
var matchDNSMsgRecursionDesiredFailData []byte

//go:embed testdata/dnsmsg_recursion_desired_success.json
var matchDNSMsgRecursionDesiredValidData []byte

var _ = Describe("RecursionDesired", func() {
	Context("NewMatchDNSMsgRecursionDesired", func() {
		var (
			m   matcher.DnsMsgMatcher
			err error
		)
		When("arg is bool", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgRecursionDesired(true)
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("arg is not bool", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgRecursionDesired("true")
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
				err = json.Unmarshal(matchDNSMsgRecursionDesiredValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "RD",
					Type: matcher.MatcherTypeDnsMsg,
					Arg:  true,
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgRecursionDesiredFailData, mc)
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
			m1, err = matcher.NewMatchDNSMsgRecursionDesired(true)
			Expect(err).To(Succeed())
		})
		When("Name is RecursionDesired", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "RecursionDesired",
					Arg:  true,
				})
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m2).To(Equal(m1))
			})
		})
		When("Name is RD", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "RD",
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
				m, err = matcher.NewMatchDNSMsgRecursionDesired(true)
				Expect(err).To(Succeed())
			})
			When("msg.RecursionDesired = true", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: true}})).To(BeTrue())
				})
			})
			When("msg.RecursionDesired = false", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: false}})).To(BeFalse())
				})
			})
		})
		When("match false", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgRecursionDesired(false)
				Expect(err).To(Succeed())
			})
			When("msg.RecursionDesired = true", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: true}})).To(BeFalse())
				})
			})
			When("msg.RecursionDesired = false", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: false}})).To(BeTrue())
				})
			})
		})
	})
})
