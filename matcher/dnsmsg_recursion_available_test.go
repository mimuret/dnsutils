package matcher_test

import (
	_ "embed"
	"encoding/json"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/dnsmsg_recursion_available_fail.json
var matchDNSMsgRecursionAvailableFailData []byte

//go:embed testdata/dnsmsg_recursion_available_success.json
var matchDNSMsgRecursionAvailableValidData []byte

var _ = Describe("RecursionAvailable", func() {
	Context("NewMatchDNSMsgRecursionAvailable", func() {
		var (
			m   matcher.DnsMsgMatcher
			err error
		)
		When("arg is bool", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgRecursionAvailable(true)
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("arg is not bool", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgRecursionAvailable("true")
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
				err = json.Unmarshal(matchDNSMsgRecursionAvailableValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "RA",
					Type: matcher.MatcherTypeDnsMsg,
					Arg:  true,
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgRecursionAvailableFailData, mc)
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
			m1, err = matcher.NewMatchDNSMsgRecursionAvailable(true)
			Expect(err).To(Succeed())
		})
		When("Name is RecursionAvailable", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "RecursionAvailable",
					Arg:  true,
				})
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m2).To(Equal(m1))
			})
		})
		When("Name is RA", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "RA",
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
				m, err = matcher.NewMatchDNSMsgRecursionAvailable(true)
				Expect(err).To(Succeed())
			})
			When("msg.RecursionAvailable = true", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{RecursionAvailable: true}})).To(BeTrue())
				})
			})
			When("msg.RecursionAvailable = false", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{RecursionAvailable: false}})).To(BeFalse())
				})
			})
		})
		When("match false", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgRecursionAvailable(false)
				Expect(err).To(Succeed())
			})
			When("msg.RecursionAvailable = true", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{RecursionAvailable: true}})).To(BeFalse())
				})
			})
			When("msg.RecursionAvailable = false", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{RecursionAvailable: false}})).To(BeTrue())
				})
			})
		})
	})
})
