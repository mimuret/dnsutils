package matcher_test

import (
	_ "embed"
	"encoding/json"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/dnsmsg_truncated_fail.json
var matchDNSMsgTruncatedFailData []byte

//go:embed testdata/dnsmsg_truncated_success.json
var matchDNSMsgTruncatedValidData []byte

var _ = Describe("Truncated", func() {
	Context("NewMatchDNSMsgTruncated", func() {
		var (
			m   matcher.DnsMsgMatcher
			err error
		)
		When("arg is bool", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgTruncated(true)
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("arg is not bool", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgTruncated("true")
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
				err = json.Unmarshal(matchDNSMsgTruncatedValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "TC",
					Type: matcher.MatcherTypeDnsMsg,
					Arg:  true,
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgTruncatedFailData, mc)
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
			m1, err = matcher.NewMatchDNSMsgTruncated(true)
			Expect(err).To(Succeed())
		})
		When("Name is Truncated", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "Truncated",
					Arg:  true,
				})
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m2).To(Equal(m1))
			})
		})
		When("Name is TC", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "TC",
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
				m, err = matcher.NewMatchDNSMsgTruncated(true)
				Expect(err).To(Succeed())
			})
			When("msg.Truncated = true", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{Truncated: true}})).To(BeTrue())
				})
			})
			When("msg.Truncated = false", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{Truncated: false}})).To(BeFalse())
				})
			})
		})
		When("match false", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgTruncated(false)
				Expect(err).To(Succeed())
			})
			When("msg.Truncated = true", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{Truncated: true}})).To(BeFalse())
				})
			})
			When("msg.Truncated = false", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{Truncated: false}})).To(BeTrue())
				})
			})
		})
	})
})
