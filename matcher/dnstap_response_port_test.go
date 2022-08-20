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

//go:embed testdata/dnstap_response_port_fail.json
var matchDnstapResponsePortFailData []byte

//go:embed testdata/dnstap_response_port_success.json
var matchDnstapResponsePortValidData []byte

var _ = Describe("ResponsePort", func() {
	Context("NewMatchResponsePort", func() {
		var (
			m   matcher.DnstapMatcher
			err error
		)
		When("arg is uint", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchResponsePort(uint(1))
			})
			It("returns matcher", func() {
				Expect(err).To(Succeed())
				Expect(m).NotTo(BeNil())
			})
		})
		When("invalid range", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchResponsePort(uint64(math.MaxUint64))
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchResponsePort(true)
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
				err = json.Unmarshal(matchDnstapResponsePortValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "ResponsePort",
					Type: matcher.MatcherTypeDnstap,
					Arg:  uint32(853),
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDnstapResponsePortFailData, mc)
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
			m1, err = matcher.NewMatchResponsePort(1)
			Expect(err).To(Succeed())
		})
		When("Name is ResponsePort", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnstapMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnstap,
					Name: "ResponsePort",
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
				m, err = matcher.NewMatchResponsePort(uint64(0))
				Expect(err).To(Succeed())
			})
			When("msg is nil", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{})).To(BeFalse())
				})
			})
			When("msg.ResponsePort is nil", func() {
				It("returns true", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{},
					})).To(BeTrue())
				})
			})
		})
		When("match 1", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchResponsePort(uint64(1))
				Expect(err).To(Succeed())
			})
			When("msg is nil", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{})).To(BeFalse())
				})
			})
			When("msg.ResponsePort is nil", func() {
				It("returns true", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{},
					})).To(BeFalse())
				})
			})
			When("msg.ResponsePort = TARGET", func() {
				It("returns true", func() {
					u32 := uint32(1)
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							ResponsePort: &u32,
						},
					})).To(BeTrue())
				})
			})
			When("msg.ResponsePort != TARGET", func() {
				It("returns false", func() {
					u32 := uint32(2)
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							ResponsePort: &u32,
						},
					})).To(BeFalse())
				})
			})
		})
	})
})
