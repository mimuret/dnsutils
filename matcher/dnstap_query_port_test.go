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

//go:embed testdata/dnstap_query_port_fail.json
var matchDnstapQueryPortFailData []byte

//go:embed testdata/dnstap_query_port_success.json
var matchDnstapQueryPortValidData []byte

var _ = Describe("QueryPort", func() {
	Context("NewMatchQueryPort", func() {
		var (
			m   matcher.DnstapMatcher
			err error
		)
		When("arg is uint", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchQueryPort(uint(1))
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("invalid range", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchQueryPort(uint64(math.MaxUint64))
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchQueryPort(true)
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
				err = json.Unmarshal(matchDnstapQueryPortValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "QueryPort",
					Type: matcher.MatcherTypeDnstap,
					Arg:  uint32(53),
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDnstapQueryPortFailData, mc)
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
			m1, err = matcher.NewMatchQueryPort(1)
			Expect(err).To(Succeed())
		})
		When("Name is QueryPort", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnstapMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnstap,
					Name: "QueryPort",
					Arg:  uint32(1),
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
				m, err = matcher.NewMatchQueryPort(uint64(0))
				Expect(err).To(Succeed())
			})
			When("msg is nil", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{})).To(BeFalse())
				})
			})
			When("msg.QueryPort is nil", func() {
				It("returns true", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{},
					})).To(BeTrue())
				})
			})
		})
		When("match 1", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchQueryPort(uint64(1))
				Expect(err).To(Succeed())
			})
			When("msg is nil", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{})).To(BeFalse())
				})
			})
			When("msg.QueryPort is nil", func() {
				It("returns true", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{},
					})).To(BeFalse())
				})
			})
			When("msg.QueryPort = TARGET", func() {
				It("returns true", func() {
					u32 := uint32(1)
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							QueryPort: &u32,
						},
					})).To(BeTrue())
				})
			})
			When("msg.QueryPort != TARGET", func() {
				It("returns false", func() {
					u32 := uint32(2)
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							QueryPort: &u32,
						},
					})).To(BeFalse())
				})
			})
		})
	})
})
