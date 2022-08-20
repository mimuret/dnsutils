package matcher_test

import (
	_ "embed"
	"encoding/json"
	"regexp"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/dnsmsg_query_name_regexp_fail.json
var matchDNSMsgQueryNameRegexpFailData []byte

//go:embed testdata/dnsmsg_query_name_regexp_success.json
var matchDNSMsgQueryNameRegexpValidData []byte

var _ = Describe("QNameRegexpRegexp", func() {
	Context("NewMatchDNSMsgQueryNameRegexp", func() {
		var (
			m   matcher.DnsMsgMatcher
			err error
		)
		When("arg is string", func() {
			When("valid arg", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgQueryNameRegexp("^.*exmaple\\.jp$")
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid arg", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgQueryNameRegexp("*")
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is regexp", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgQueryNameRegexp(regexp.MustCompile(".*"))
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgQueryNameRegexp(true)
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
				err = json.Unmarshal(matchDNSMsgQueryNameRegexpValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "QNameRegexp",
					Type: matcher.MatcherTypeDnsMsg,
					Arg:  ".*",
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgQueryNameRegexpFailData, mc)
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
			m1, err = matcher.NewMatchDNSMsgQueryNameRegexp(regexp.MustCompile(".*"))
			Expect(err).To(Succeed())
		})
		When("Name is QNameRegexp", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "QNameRegexp",
					Arg:  ".*",
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
				m, err = matcher.NewMatchDNSMsgQueryNameRegexp(".*\\.exmaple\\.jp")
				Expect(err).To(Succeed())
			})
			When("msg.Question is empty ", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{})).To(BeFalse())
				})
			})
			When("msg.QueryNameRegexp = TARGET", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{Question: []dns.Question{{Name: "hoge.exmaple.jp"}}})).To(BeTrue())
				})
			})
			When("msg.QueryNameRegexp != TARGET", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{Question: []dns.Question{{Name: "exmaple.jp"}}})).To(BeFalse())
				})
			})
		})
	})
})
