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

//go:embed testdata/dnstap_family_fail.json
var matchDnstapMessageFamilyFailData []byte

//go:embed testdata/dnstap_family_success.json
var matchDnstapMessageFamilyValidData []byte

var _ = Describe("MessageFamily", func() {
	Context("NewMatchMessageFamily", func() {
		var (
			m   matcher.DnstapMatcher
			err error
		)
		When("arg is string", func() {
			When("valid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchMessageFamily("INET")
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchMessageFamily("inet")
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is int", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageFamily(1)
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("arg is dnstap.SocketFamily", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageFamily(dnstap.SocketFamily(1))
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("invalid range", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageFamily(uint64(math.MaxUint64))
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchMessageFamily(true)
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
				err = json.Unmarshal(matchDnstapMessageFamilyValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "MessageFamily",
					Type: matcher.MatcherTypeDnstap,
					Arg:  "INET6",
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDnstapMessageFamilyFailData, mc)
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
			m1, err = matcher.NewMatchMessageFamily("INET6")
			Expect(err).To(Succeed())
		})
		When("Name is MessageFamily", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnstapMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnstap,
					Name: "MessageFamily",
					Arg:  2,
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
				m, err = matcher.NewMatchMessageFamily("INET6")
				Expect(err).To(Succeed())
			})
			When("msg is nil", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{})).To(BeFalse())
				})
			})
			When("msg.MessageFamily = TARGET", func() {
				It("returns true", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							SocketFamily: dnstap.SocketFamily_INET6.Enum(),
						},
					})).To(BeTrue())
				})
			})
			When("msg.MessageFamily != TARGET", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							SocketFamily: dnstap.SocketFamily_INET.Enum(),
						},
					})).To(BeFalse())
				})
			})
		})
	})
})
