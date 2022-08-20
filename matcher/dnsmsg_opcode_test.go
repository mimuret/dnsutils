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

//go:embed testdata/dnsmsg_opcode_fail.json
var matchDNSMsgOpcodeFailData []byte

//go:embed testdata/dnsmsg_opcode_success.json
var matchDNSMsgOpcodeValidData []byte

var _ = Describe("Opcode", func() {
	Context("NewMatchDNSMsgOpcode", func() {
		var (
			m   matcher.DnsMsgMatcher
			err error
		)
		When("arg is string", func() {
			When("valid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgOpcode("QUERY")
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgOpcode("query")
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is int", func() {
			When("valid range", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgOpcode(0)
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid range", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchDNSMsgOpcode(uint64(math.MaxUint64))
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgOpcode(true)
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
				err = json.Unmarshal(matchDNSMsgOpcodeValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "Opcode",
					Type: matcher.MatcherTypeDnsMsg,
					Arg:  "QUERY",
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDNSMsgOpcodeFailData, mc)
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
			m1, err = matcher.NewMatchDNSMsgOpcode("QUERY")
			Expect(err).To(Succeed())
		})
		When("Name is Opcode", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnsMsgMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnsMsg,
					Name: "Opcode",
					Arg:  "QUERY",
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
				m, err = matcher.NewMatchDNSMsgOpcode("QUERY")
				Expect(err).To(Succeed())
			})
			When("msg.Opcode = TARGET", func() {
				It("returns true", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeQuery}})).To(BeTrue())
				})
			})
			When("msg.Opcode != TARGET", func() {
				It("returns false", func() {
					Expect(m.Match(&dns.Msg{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeUpdate}})).To(BeFalse())
				})
			})
		})
	})
})
