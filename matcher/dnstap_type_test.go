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

//go:embed testdata/dnstap_type_fail.json
var matchDnstapMessageTypeFailData []byte

//go:embed testdata/dnstap_type_success.json
var matchDnstapMessageTypeValidData []byte

var _ = Describe("MessageType", func() {
	Context("NewMatchMessageType", func() {
		var (
			m   matcher.DnstapMatcher
			err error
		)
		When("arg is string", func() {
			When("valid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchMessageType("RESOLVER_RESPONSE")
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchMessageType("resolver_response")
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is int", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageType(1)
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("invalid range", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageType(uint64(math.MaxUint64))
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("arg is dnstap.Message_Type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageType(dnstap.Message_AUTH_QUERY)
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageType(true)
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
				err = json.Unmarshal(matchDnstapMessageTypeValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "MessageType",
					Type: matcher.MatcherTypeDnstap,
					Arg:  "AUTH_RESPONSE",
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDnstapMessageTypeFailData, mc)
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
			m1, err = matcher.NewMatchMessageType("AUTH_RESPONSE")
			Expect(err).To(Succeed())
		})
		When("Name is MessageType", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnstapMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnstap,
					Name: "MessageType",
					Arg:  int32(2),
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
		When("match 0", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageType(dnstap.Message_AUTH_QUERY)
				Expect(err).To(Succeed())
			})
			When("msg is nil", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{})).To(BeFalse())
				})
			})
			When("msg.MessageType is nil", func() {
				It("returns true", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{},
					})).To(BeTrue())
				})
			})
		})
		When("match 1", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageType(dnstap.Message_AUTH_RESPONSE)
				Expect(err).To(Succeed())
			})
			When("msg is nil", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{})).To(BeFalse())
				})
			})
			When("msg.MessageType is nil", func() {
				It("returns true", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{},
					})).To(BeFalse())
				})
			})
			When("msg.MessageType = TARGET", func() {
				It("returns true", func() {
					mtype := dnstap.Message_AUTH_RESPONSE
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							Type: &mtype,
						},
					})).To(BeTrue())
				})
			})
			When("msg.MessageType != TARGET", func() {
				It("returns false", func() {
					mtype := dnstap.Message_AUTH_QUERY
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							Type: &mtype,
						},
					})).To(BeFalse())
				})
			})
		})
	})
})
