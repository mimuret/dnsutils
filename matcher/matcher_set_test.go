package matcher_test

import (
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MatcherSet", func() {
	var (
		ok                         bool
		m, trueSubset, falseSubset *matcher.MatcherSet
		staticTrueDnstapMatcher    matcher.DnstapMatcher
		staticFalseDnstapMatcher   matcher.DnstapMatcher
		staticTrueDnsMsgMatcher    matcher.DnsMsgMatcher
		staticFalseDnsMsgMatcher   matcher.DnsMsgMatcher
	)
	BeforeEach(func() {
		m = matcher.NewMatcherSet()
		trueSubset = matcher.NewMatcherSet()
		falseSubset = matcher.NewMatcherSet()
		staticTrueDnstapMatcher, _ = matcher.NewMatchDnstapStatic(true)
		staticFalseDnstapMatcher, _ = matcher.NewMatchDnstapStatic(false)
		staticTrueDnsMsgMatcher, _ = matcher.NewMatchDNSMsgStatic(true)
		staticFalseDnsMsgMatcher, _ = matcher.NewMatchDNSMsgStatic(false)

		trueSubset.DnstapMatchers = append(trueSubset.DnstapMatchers, staticTrueDnstapMatcher)
		trueSubset.DnsMsgMatchers = append(trueSubset.DnsMsgMatchers, staticTrueDnsMsgMatcher)
		falseSubset.DnstapMatchers = append(falseSubset.DnstapMatchers, staticFalseDnstapMatcher)
		falseSubset.DnsMsgMatchers = append(falseSubset.DnsMsgMatchers, staticFalseDnsMsgMatcher)
	})
	Context("MatchDnstap", func() {
		When("invalid is true", func() {
			BeforeEach(func() {
				m.Invalid = true
			})
			When("OpCode is AND", func() {
				BeforeEach(func() {
					m.Op = matcher.SetOpAND
				})
				When("DnstapMatchers, DnsMsgMatchers and SubSets are empty", func() {
					It("returns true", func() {
						Expect(m.Match(nil, nil)).To(BeTrue())
					})
				})
				When("DnstapMatchers returns false", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticFalseDnstapMatcher)
					})
					It("returns true", func() {
						Expect(m.Match(nil, nil)).To(BeTrue())
					})
				})
				When("DnstapMatchers returns true", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticTrueDnstapMatcher)
					})
					It("returns false", func() {
						Expect(m.Match(nil, nil)).To(BeFalse())
					})
				})
			})
		})
		When("OpCode is AND", func() {
			BeforeEach(func() {
				m.Op = matcher.SetOpAND
			})
			When("DnstapMatchers is empty", func() {
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnstap(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnstap(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.MatchDnstap(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
			})
			When("DnstapMatchers return false", func() {
				BeforeEach(func() {
					m.DnstapMatchers = append(m.DnstapMatchers, staticFalseDnstapMatcher)
				})
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnstap(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnstap(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.Match(nil, nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
			})
			When("DnstapMatchers return true", func() {
				BeforeEach(func() {
					m.DnstapMatchers = append(m.DnstapMatchers, staticTrueDnstapMatcher)
				})
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnstap(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnstap(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.MatchDnstap(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
			})
		})
		When("OpCode is OR", func() {
			BeforeEach(func() {
				m.Op = matcher.SetOpOR
			})
			When("DnstapMatchers is empty", func() {
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnstap(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnstap(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.MatchDnstap(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
			})
			When("DnstapMatchers return false", func() {
				BeforeEach(func() {
					m.DnstapMatchers = append(m.DnstapMatchers, staticFalseDnstapMatcher)
				})
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnstap(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnstap(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.MatchDnstap(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
			})
			When("DnstapMatchers return true", func() {
				BeforeEach(func() {
					m.DnstapMatchers = append(m.DnstapMatchers, staticTrueDnstapMatcher)
				})
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnstap(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnstap(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.MatchDnstap(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
			})
		})
	})
	Context("MatchDnsMsg", func() {
		When("OpCode is AND", func() {
			BeforeEach(func() {
				m.Op = matcher.SetOpAND
			})
			When("DnsMsgMatchers is empty", func() {
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnsMsg(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
			})
			When("DnsMsgMatchers returns false", func() {
				BeforeEach(func() {
					m.DnsMsgMatchers = append(m.DnsMsgMatchers, staticFalseDnsMsgMatcher)
				})
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnsMsg(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
			})
			When("DnsMsgMatchers returns true", func() {
				BeforeEach(func() {
					m.DnsMsgMatchers = append(m.DnsMsgMatchers, staticTrueDnsMsgMatcher)
				})
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnsMsg(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
			})
		})
		When("OpCode is OR", func() {
			BeforeEach(func() {
				m.Op = matcher.SetOpOR
			})
			When("DnsMsgMatchers is empty", func() {
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnsMsg(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
			})
			When("DnsMsgMatchers returns false", func() {
				BeforeEach(func() {
					m.DnsMsgMatchers = append(m.DnsMsgMatchers, staticFalseDnsMsgMatcher)
				})
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnsMsg(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeFalse())
					})
				})
			})
			When("DnsMsgMatchers returns true", func() {
				BeforeEach(func() {
					m.DnsMsgMatchers = append(m.DnsMsgMatchers, staticTrueDnsMsgMatcher)
				})
				When("SubSets is empty", func() {
					BeforeEach(func() {
						ok = m.MatchDnsMsg(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return true", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, trueSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns true", func() {
						Expect(ok).To(BeTrue())
					})
				})
				When("SubSets return false", func() {
					BeforeEach(func() {
						m.SubSets = append(m.SubSets, falseSubset)
						ok = m.MatchDnsMsg(nil)
					})
					It("returns false", func() {
						Expect(ok).To(BeTrue())
					})
				})
			})
		})
	})
	Context("Match", func() {
		When("OpCode is AND", func() {
			When("DnsMsgMatchers is empty", func() {
				When("DnstapMatchers is empty", func() {
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
				When("DnstapMatchers return false", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticFalseDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
				When("DnstapMatchers return true", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticTrueDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
			})
			When("DnsMsgMatchers returns false", func() {
				BeforeEach(func() {
					m.DnsMsgMatchers = append(m.DnsMsgMatchers, staticFalseDnsMsgMatcher)
				})
				When("DnstapMatchers is empty", func() {
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
				When("DnstapMatchers return false", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticFalseDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
				When("DnstapMatchers return true", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticTrueDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
			})
			When("DnsMsgMatchers returns true", func() {
				BeforeEach(func() {
					m.DnsMsgMatchers = append(m.DnsMsgMatchers, staticTrueDnsMsgMatcher)
				})
				When("DnstapMatchers is empty", func() {
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
				When("DnstapMatchers return false", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticFalseDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
				When("DnstapMatchers return true", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticTrueDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
			})
		})
		When("OpCode is OR", func() {
			BeforeEach(func() {
				m.Op = matcher.SetOpOR
			})
			When("DnsMsgMatchers is empty", func() {
				When("DnstapMatchers is empty", func() {
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
				When("DnstapMatchers return false", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticFalseDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
				When("DnstapMatchers return true", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticTrueDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
				})
			})
			When("DnsMsgMatchers returns false", func() {
				BeforeEach(func() {
					m.DnsMsgMatchers = append(m.DnsMsgMatchers, staticFalseDnsMsgMatcher)
				})
				When("DnstapMatchers is empty", func() {
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
				When("DnstapMatchers return false", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticFalseDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns false", func() {
							Expect(ok).To(BeFalse())
						})
					})
				})
				When("DnstapMatchers return true", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticTrueDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
				})
			})
			When("DnsMsgMatchers returns true", func() {
				BeforeEach(func() {
					m.DnsMsgMatchers = append(m.DnsMsgMatchers, staticTrueDnsMsgMatcher)
				})
				When("DnstapMatchers is empty", func() {
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
				})
				When("DnstapMatchers return false", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticFalseDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
				})
				When("DnstapMatchers return true", func() {
					BeforeEach(func() {
						m.DnstapMatchers = append(m.DnstapMatchers, staticTrueDnstapMatcher)
					})
					When("SubSets is empty", func() {
						BeforeEach(func() {
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return true", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, trueSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
					When("SubSets return false", func() {
						BeforeEach(func() {
							m.SubSets = append(m.SubSets, falseSubset)
							ok = m.Match(nil, nil)
						})
						It("returns true", func() {
							Expect(ok).To(BeTrue())
						})
					})
				})
			})
		})
	})
})
