package matcher_test

import (
	_ "embed"
	"encoding/json"
	"net"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/dnstap_response_address_fail.json
var matchDnstapResponseAddressFailData []byte

//go:embed testdata/dnstap_response_address_success.json
var matchDnstapResponseAddressValidData []byte

var _ = Describe("ResponseAddress", func() {
	Context("NewMatchResponseAddress", func() {
		var (
			m   matcher.DnstapMatcher
			err error
		)
		When("arg is string", func() {
			When("valid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchResponseAddress("192.168.0.0/24")
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
			When("invalid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchResponseAddress("192.168.0.1")
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		When("arg is net.IPNet", func() {
			When("valid string", func() {
				BeforeEach(func() {
					m, err = matcher.NewMatchResponseAddress(&net.IPNet{})
				})
				It("returns matcher", func() {
					Expect(err).To(Succeed())
					Expect(m).NotTo(BeNil())
				})
			})
		})
		When("arg is invalid type", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchResponseAddress(true)
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
				err = json.Unmarshal(matchDnstapResponseAddressValidData, mc)
			})
			It("not returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{
					Name: "ResponseAddress",
					Type: matcher.MatcherTypeDnstap,
					Arg:  "192.168.0.0/24",
				}))
			})
		})
		When("invalid arg", func() {
			BeforeEach(func() {
				err = json.Unmarshal(matchDnstapResponseAddressFailData, mc)
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
			m1, err = matcher.NewMatchResponseAddress("192.168.0.0/24")
			Expect(err).To(Succeed())
		})
		When("Name is ResponseAddress", func() {
			BeforeEach(func() {
				m2, err = matcher.BuildDnstapMatcher(matcher.MatcherConfig{
					Type: matcher.MatcherTypeDnstap,
					Name: "ResponseAddress",
					Arg: net.IPNet{
						IP:   net.IPv4(192, 168, 0, 0).To4(),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
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
				m, err = matcher.NewMatchResponseAddress("192.168.0.0/24")
				Expect(err).To(Succeed())
			})
			When("msg is nil", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{})).To(BeFalse())
				})
			})
			When("msg.ResponseAddress is nil", func() {
				It("returns true", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{},
					})).To(BeFalse())
				})
			})
			When("msg.ResponseAddress = TARGET", func() {
				It("returns true", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							ResponseAddress: net.IPv4(192, 168, 0, 255),
						},
					})).To(BeTrue())
				})
			})
			When("msg.ResponseAddress != TARGET", func() {
				It("returns false", func() {
					Expect(m.Match(&dnstap.Dnstap{
						Message: &dnstap.Message{
							ResponseAddress: net.IPv4(192, 168, 1, 0),
						},
					})).To(BeFalse())
				})
			})
		})
	})
})
