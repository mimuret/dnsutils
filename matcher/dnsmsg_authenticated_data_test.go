package matcher_test

import (
	_ "embed"
	"encoding/json"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/dnsmsg_authenticated_data_fail.json
var matchDNSMsgAuthenticatedDataFailData []byte

//go:embed testdata/dnsmsg_authenticated_data_success.json
var matchDNSMsgAuthenticatedDataValidData []byte

var _ = Describe("AuthenticatedData", func() {
	Context("NewMatchDNSMsgAuthenticatedData", func() {
		var (
			m   matcher.DnsMsgMatcher
			err error
		)
		When("arg is bool", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgAuthenticatedData(true)
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("arg is not bool", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgAuthenticatedData("true")
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
				err = json.Unmarshal(matchDNSMsgAuthenticatedDataValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "AD",
					Type: matcher.MatcherTypeDnsMsg,
					Arg:  true,
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgAuthenticatedDataFailData, mc)
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
			m1, err = matcher.NewMatchDNSMsgAuthenticatedData(true)
			Expect(err).To(Succeed())
		})
		When("Name is AuthenticatedData", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "AuthenticatedData",
					Arg:  true,
				})
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m2).To(Equal(m1))
			})
		})
		When("Name is AD", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "AD",
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
				m, err = matcher.NewMatchDNSMsgAuthenticatedData(true)
				Expect(err).To(Succeed())
			})
			When("msg.AuthenticatedData = true", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{AuthenticatedData: true}})).To(BeTrue())
				})
			})
			When("msg.AuthenticatedData = false", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{AuthenticatedData: false}})).To(BeFalse())
				})
			})
		})
		When("match false", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgAuthenticatedData(false)
				Expect(err).To(Succeed())
			})
			When("msg.AuthenticatedData = true", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{AuthenticatedData: true}})).To(BeFalse())
				})
			})
			When("msg.AuthenticatedData = false", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{AuthenticatedData: false}})).To(BeTrue())
				})
			})
		})
	})
})
