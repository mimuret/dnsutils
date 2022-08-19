package matcher_test

import (
	_ "embed"
	"encoding/json"
	"math"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/dnstap_protocol_fail.json
var matchDnstapMessageProtocolFailData []byte

//go:embed testdata/dnstap_protocol_success.json
var matchDnstapMessageProtocolValidData []byte

var _ = Describe("MessageProtocol", func() {
	Context("NewMatchMessageProtocol", func() {
		var (
			m   matcher.DnstapMatcher
			err error
		)
		When("arg is string", func() {
			When("valid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchMessageProtocol("DOH")
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchMessageProtocol("doh")
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is int", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageProtocol(1)
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("invalid range", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageProtocol(uint64(math.MaxUint64))
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("arg is dnstap.SocketProtocol", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageProtocol(dnstap.SocketProtocol(1))
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageProtocol(true)
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
				err = json.Unmarshal(matchDnstapMessageProtocolValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "MessageProtocol",
					Type: matcher.MatcherTypeDnstap,
					Arg:  "UDP",
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDnstapMessageProtocolFailData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
	})
	Context("BuildDnsMsgMatcher", func() {
		var (
			err error
			m1  matcher.DnstapMatcher
			m2  matcher.DnstapMatcher
		)
		BeforeEach(func() {
			m1, err = matcher.NewMatchMessageProtocol("DOT")
			Expect(err).To(Succeed())
		})
		When("Name is MessageProtocol", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnstapMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnstap,
					Name: "MessageProtocol",
					Arg:  3,
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
			m   matcher.DnstapMatcher
		)
		When("match true", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageProtocol("TCP")
				Expect(err).To(Succeed())
			})
			When("msg is nil", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{})).To(BeFalse())
				})
			})
			When("msg.MessageProtocol = TARGET", func() {
				It("returns true", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							SocketProtocol: dnstap.SocketProtocol_TCP.Enum(),
						},
					})).To(BeTrue())
				})
			})
			When("msg.MessageProtocol != TARGET", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							SocketProtocol: dnstap.SocketProtocol_UDP.Enum(),
						},
					})).To(BeFalse())
				})
			})
		})
	})
})
