package matcher_test

import (
	_ "embed"
	"encoding/json"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/dnsmsg_query_name_subdomain_fail.json
var matchDNSMsgQuerySubDomainFailData []byte

//go:embed testdata/dnsmsg_query_name_subdomain_success.json
var matchDNSMsgQuerySubDomainValidData []byte

var _ = Describe("QName", func() {
	Context("NewMatchDNSMsgQueryNameSubDomain", func() {
		var (
			m   matcher.DnsMsgMatcher
			err error
		)
		When("arg is string", func() {
			When("valid domain name", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgQueryNameSubDomain("exmaple.jp")
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid domain name", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgQueryNameSubDomain("..")
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgQueryNameSubDomain(true)
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
				err = json.Unmarshal(matchDNSMsgQuerySubDomainValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "QNameSubDomain",
					Type: matcher.MatcherTypeDnsMsg,
					Arg:  "example.jp.",
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgQuerySubDomainFailData, mc)
			})
			It("returns error", func() {
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
			m1, err = matcher.NewMatchDNSMsgQueryNameSubDomain("exmaple.jp")
			Expect(err).To(Succeed())
		})
		When("Name is QName", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "QNameSubDomain",
					Arg:  "exmaple.jp",
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
		BeforeEach(func() {
			m, err = matcher.NewMatchDNSMsgQueryNameSubDomain("exmaple.jp.")
			Expect(err).To(Succeed())
		})
		When("msg.Question is empty ", func() {
			It("returns false", func() {
				Expect(m.Match(&dns.Msg{})).To(BeFalse())
			})
		})
		When("msg.Question is not domain name ", func() {
			It("returns false", func() {
				Expect(m.Match(&dns.Msg{Question: []dns.Question{
					{
						Name:   "..",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassCHAOS,
					},
				}})).To(BeFalse())
			})
		})
		When("msg.QueryName != TARGET", func() {
			It("returns false", func() {
				Expect(m.Match(&dns.Msg{Question: []dns.Question{{Name: "exmaple.net"}}})).To(BeFalse())
			})
			It("returns false", func() {
				Expect(m.Match(&dns.Msg{Question: []dns.Question{{Name: "jp"}}})).To(BeFalse())
			})
			It("returns false", func() {
				Expect(m.Match(&dns.Msg{Question: []dns.Question{{Name: "ple.jp"}}})).To(BeFalse())
			})
		})
		When("msg.QueryName = SUBDOMAIN", func() {
			It("returns true", func() {
				Expect(m.Match(&dns.Msg{Question: []dns.Question{{Name: "www.ExmapLe.jp"}}})).To(BeTrue())
			})
			It("returns true", func() {
				Expect(m.Match(&dns.Msg{Question: []dns.Question{{Name: "*.ExmapLe.jp"}}})).To(BeTrue())
			})
		})
		When("msg.QueryName = TARGET", func() {
			When("different case", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{Question: []dns.Question{{Name: "ExmapLe.jp."}}})).To(BeTrue())
				})
			})
			When("not FQDN", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{Question: []dns.Question{{Name: "ExmapLe.jp"}}})).To(BeTrue())
				})
			})
		})
	})
})
