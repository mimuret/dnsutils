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

//go:embed testdata/dnsmsg_ede_fail.json
var matchDNSMsgEDEFailData []byte

//go:embed testdata/dnsmsg_ede_success.json
var matchDNSMsgEDEValidData []byte

var _ = Describe("EDE", func() {
	Context("NewMatchDNSMsgEDE", func() {
		var (
			m   matcher.DnsMsgMatcher
			err error
		)
		When("arg is string", func() {
			When("valid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgEDE("DNSSECBogus")
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgEDE("query")
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is int", func() {
			When("valid range", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgEDE(0)
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid range", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgEDE(uint64(math.MaxUint64))
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgEDE(true)
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
				err = json.Unmarshal(matchDNSMsgEDEValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "EDE",
					Type: matcher.MatcherTypeDnsMsg,
					Arg:  "OtherError",
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgEDEFailData, mc)
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
			m1, err = matcher.NewMatchDNSMsgEDE("DNSSECBogus")
			Expect(err).To(Succeed())
		})
		When("Name is EDE", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "EDE",
					Arg:  "DNSSECBogus",
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

			opt                                           *dns.OPT
			edeDNSBogus, edeStaleAnswer, edeRRSIGsMissing *dns.EDNS0_EDE
		)
		BeforeEach(func() {
			opt = new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.SetUDPSize(1323)
			edeDNSBogus = new(dns.EDNS0_EDE)
			edeDNSBogus.InfoCode = dns.ExtendedErrorCodeDNSBogus
			edeStaleAnswer = new(dns.EDNS0_EDE)
			edeStaleAnswer.InfoCode = dns.ExtendedErrorCodeStaleAnswer
			edeRRSIGsMissing = new(dns.EDNS0_EDE)
			edeRRSIGsMissing.InfoCode = dns.ExtendedErrorCodeRRSIGsMissing
		})
		When("match true", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgEDE("DNSSECBogus")
				Expect(err).To(Succeed())
			})
			When("msg.EDE = TARGET", func() {
				It("returns true", func() {
					opt.Option = []dns.EDNS0{edeRRSIGsMissing, edeDNSBogus, edeStaleAnswer}
					Expect(m.Match(&dns.Msg{Extra: []dns.RR{opt}})).To(BeTrue())
				})
			})
			When("msg.EDE != TARGET", func() {
				It("returns false", func() {
					opt.Option = []dns.EDNS0{edeRRSIGsMissing, edeStaleAnswer}
					Expect(m.Match(&dns.Msg{Extra: []dns.RR{opt}})).To(BeFalse())
				})
			})
			When("msg.EDE is empty", func() {
				It("returns false", func() {
					opt.Option = []dns.EDNS0{}
					Expect(m.Match(&dns.Msg{Extra: []dns.RR{opt}})).To(BeFalse())
				})
			})
		})
	})
})
