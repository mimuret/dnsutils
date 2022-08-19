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

//go:embed testdata/dnsmsg_query_class_fail.json
var matchDNSMsgQueryClassFailData []byte

//go:embed testdata/dnsmsg_query_class_success.json
var matchDNSMsgQueryClassValidData []byte

var _ = Describe("QClass", func() {
	Context("NewMatchDNSMsgQueryClass", func() {
		var (
			m   matcher.DnsMsgMatcher
			err error
		)
		When("arg is string", func() {
			When("valid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgQueryClass("IN")
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgQueryClass("in")
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is int", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgQueryClass(dns.ClassINET)
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("invalid range", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgQueryClass(uint64(math.MaxUint64))
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgQueryClass(true)
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
				err = json.Unmarshal(matchDNSMsgQueryClassValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "QClass",
					Type: matcher.MatcherTypeDnsMsg,
					Arg:  "IN",
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgQueryClassFailData, mc)
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
			m1, err = matcher.NewMatchDNSMsgQueryClass("IN")
			Expect(err).To(Succeed())
		})
		When("Name is QClass", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "QClass",
					Arg:  "IN",
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
				m, err = matcher.NewMatchDNSMsgQueryClass("IN")
				Expect(err).To(Succeed())
			})
			When("msg.Question is empty ", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{})).To(BeFalse())
				})
			})
			When("msg.QueryClass = TARGET", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{Question: []dns.Question{{Qclass: dns.ClassINET}}})).To(BeTrue())
				})
			})
			When("msg.QueryClass != TARGET", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{Question: []dns.Question{{Qclass: dns.ClassCHAOS}}})).To(BeFalse())
				})
			})
		})
	})
})
