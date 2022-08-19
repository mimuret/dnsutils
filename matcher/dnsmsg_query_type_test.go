package matcher_test

import (
	_ "embed"
	"encoding/json"
	"math"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/dnsmsg_query_type_fail.json
var matchDNSMsgQueryTypeFailData []byte

//go:embed testdata/dnsmsg_query_type_success.json
var matchDNSMsgQueryTypeValidData []byte

var _ = Describe("QType", func() {
	Context("NewMatchDNSMsgQueryType", func() {
		var (
			m   matcher.DnsMsgMatcher
			err error
		)
		When("arg is string", func() {
			When("valid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgQueryType("AAAA")
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgQueryType("_A_")
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is int", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgQueryType(255)
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("invalid range", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgQueryType(uint64(math.MaxUint64))
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgQueryType(true)
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
				err = json.Unmarshal(matchDNSMsgQueryTypeValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "QType",
					Type: matcher.MatcherTypeDnsMsg,
					Arg:  "A",
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgQueryTypeFailData, mc)
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
			m1, err = matcher.NewMatchDNSMsgQueryType("A")
			Expect(err).To(Succeed())
		})
		When("Name is QType", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "QType",
					Arg:  "A",
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
				m, err = matcher.NewMatchDNSMsgQueryType("A")
				Expect(err).To(Succeed())
			})
			When("msg.Question is empty ", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{})).To(BeFalse())
				})
			})
			When("msg.QueryType = TARGET", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{Question: []dns.Question{{Qtype: dns.TypeA}}})).To(BeTrue())
				})
			})
			When("msg.QueryType != TARGET", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{Question: []dns.Question{{Qtype: dns.TypeAAAA}}})).To(BeFalse())
				})
			})
		})
	})
})
