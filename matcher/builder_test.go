package matcher_test

import (
	_ "embed"

	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	var (
		err error
		mc  matcher.MatcherConfig
		c   *matcher.Config
		set *matcher.MatcherSet
	)
	BeforeEach(func() {
		mc = matcher.MatcherConfig{}
		c = &matcher.Config{}
		set = nil
	})
	Context("BuildDnstapMatcher", func() {
		var (
			m matcher.DnstapMatcher
		)
		When("MatchConfig.Type is not DNSTAP", func() {
			BeforeEach(func() {
				m, err = matcher.BuildDnstapMatcher(mc)
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("MatchConfig.Type is DNSTAP", func() {
			BeforeEach(func() {
				mc.Type = matcher.MatcherTypeDnstap
			})
			When("matcher name is not registered", func() {
				BeforeEach(func() {
					mc.Name = "Dummy"
					m, err = matcher.BuildDnstapMatcher(mc)
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
			When("matcher name is registered", func() {
				BeforeEach(func() {
					mc.Name = "Static"
				})
				When("Arg is invalid", func() {
					BeforeEach(func() {
						m, err = matcher.BuildDnstapMatcher(mc)
					})
					It("returns error", func() {
						Expect(err).To(HaveOccurred())
					})
				})
				When("Arg is valid", func() {
					BeforeEach(func() {
						mc.Arg = true
						m, err = matcher.BuildDnstapMatcher(mc)
					})
					It("returns matcher", func() {
						Expect(err).To(Succeed())
						m2, _ := matcher.NewMatchDnstapStatic(true)
						Expect(m).To(Equal(m2))
					})
				})
			})
		})
	})
	Context("BuildDnsMsgMatcher", func() {
		var (
			m matcher.DnsMsgMatcher
		)
		When("MatchConfig.Type is not DNS", func() {
			BeforeEach(func() {
				m, err = matcher.BuildDnsMsgMatcher(mc)
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("MatchConfig.Type is DNS", func() {
			BeforeEach(func() {
				mc.Type = matcher.MatcherTypeDnsMsg
			})
			When("matcher name is not registered", func() {
				BeforeEach(func() {
					mc.Name = "Dummy"
					m, err = matcher.BuildDnsMsgMatcher(mc)
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
			When("matcher name is registered", func() {
				BeforeEach(func() {
					mc.Name = "Static"
				})
				When("Arg is invalid", func() {
					BeforeEach(func() {
						m, err = matcher.BuildDnsMsgMatcher(mc)
					})
					It("returns error", func() {
						Expect(err).To(HaveOccurred())
					})
				})
				When("Arg is valid", func() {
					BeforeEach(func() {
						mc.Arg = true
						m, err = matcher.BuildDnsMsgMatcher(mc)
					})
					It("returns matcher", func() {
						Expect(err).To(Succeed())
						m2, _ := matcher.NewMatchDNSMsgStatic(true)
						Expect(m).To(Equal(m2))
					})
				})
			})
		})
	})
	Context("BuilderMatchSet", func() {
		When("Op is invalid", func() {
			BeforeEach(func() {
				set, err = matcher.BuilderMatchSet(c)
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(MatchRegexp("unknown op"))
			})
		})
		When("op is valid", func() {
			BeforeEach(func() {
				c.Op = matcher.MatchOpAND
			})
			When("matcher config is invalid", func() {
				When("dnstap matcher config is invalid", func() {
					BeforeEach(func() {
						c.Matchers = append(c.Matchers, matcher.MatcherConfig{Type: matcher.MatcherTypeDnstap})
						set, err = matcher.BuilderMatchSet(c)
					})
					It("returns error", func() {
						Expect(err).To(HaveOccurred())
						Expect(err.Error()).To(MatchRegexp("failed to create dnstap matcher"))
					})
				})
				When("dns matcher config is invalid", func() {
					BeforeEach(func() {
						c.Matchers = append(c.Matchers, matcher.MatcherConfig{Type: matcher.MatcherTypeDnsMsg})
						set, err = matcher.BuilderMatchSet(c)
					})
					It("returns error", func() {
						Expect(err).To(HaveOccurred())
						Expect(err.Error()).To(MatchRegexp("failed to create dns matcher"))
					})
				})
				When("matcher config is invalid", func() {
					BeforeEach(func() {
						c.Matchers = append(c.Matchers, matcher.MatcherConfig{})
						set, err = matcher.BuilderMatchSet(c)
					})
					It("returns error", func() {
						Expect(err).To(HaveOccurred())
						Expect(err.Error()).To(MatchRegexp("unknown type"))
					})
				})
			})
			When("matcher config is valid", func() {
				When("dnstap matcher config is valid", func() {
					BeforeEach(func() {
						c.Matchers = append(c.Matchers, matcher.MatcherConfig{Type: matcher.MatcherTypeDnstap, Name: "Static", Arg: true})
						set, err = matcher.BuilderMatchSet(c)
					})
					It("returns error", func() {
						m, _ := matcher.NewMatchDnstapStatic(true)
						Expect(err).To(Succeed())
						Expect(len(set.DnstapMatchers)).To(Equal(1))
						Expect(len(set.DnsMsgMatchers)).To(Equal(0))
						Expect(len(set.SubSets)).To(Equal(0))
						Expect(set.DnstapMatchers[0]).To(Equal(m))
					})
				})
				When("dns matcher config is valid", func() {
					BeforeEach(func() {
						c.Matchers = append(c.Matchers, matcher.MatcherConfig{Type: matcher.MatcherTypeDnsMsg, Name: "Static", Arg: true})
						set, err = matcher.BuilderMatchSet(c)
					})
					It("returns error", func() {
						m, _ := matcher.NewMatchDNSMsgStatic(true)
						Expect(err).To(Succeed())
						Expect(len(set.DnstapMatchers)).To(Equal(0))
						Expect(len(set.DnsMsgMatchers)).To(Equal(1))
						Expect(len(set.SubSets)).To(Equal(0))
						Expect(set.DnsMsgMatchers[0]).To(Equal(m))
					})
				})
			})
			When("subset config is invalid", func() {
				BeforeEach(func() {
					c.SubConfigs = append(c.SubConfigs, matcher.Config{})
					set, err = matcher.BuilderMatchSet(c)
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(MatchRegexp("failed to create subset"))
				})
			})
			When("subset config is valid", func() {
				BeforeEach(func() {
					c.SubConfigs = append(c.SubConfigs, matcher.Config{
						Op: matcher.MatchOpAND,
						Matchers: []matcher.MatcherConfig{
							{
								Type: matcher.MatcherTypeDnsMsg,
								Name: "Static",
								Arg:  true,
							},
						},
					})
					set, err = matcher.BuilderMatchSet(c)
				})
				It("returns error", func() {
					Expect(err).To(Succeed())
					m, _ := matcher.NewMatchDNSMsgStatic(true)
					Expect(err).To(Succeed())
					Expect(len(set.DnstapMatchers)).To(Equal(0))
					Expect(len(set.DnsMsgMatchers)).To(Equal(0))
					Expect(len(set.SubSets)).To(Equal(1))
					subset := set.SubSets[0]
					Expect(len(subset.DnstapMatchers)).To(Equal(0))
					Expect(len(subset.DnsMsgMatchers)).To(Equal(1))
					Expect(len(subset.SubSets)).To(Equal(0))
					Expect(subset.DnsMsgMatchers[0]).To(Equal(m))
				})
			})
		})
	})
})
