package matcher_test

import (
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Static", func() {
	Context("matchStaticDnstap", func() {
		var (
			err error
			m   matcher.DnstapMatcher
			ok  bool
		)
		When("true", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDnstapStatic(true)
				Expect(err).To(Succeed())
				ok = m.Match(nil)
			})
			It("returns true", func() {
				Expect(ok).To(BeTrue())
			})
		})
		When("false", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDnstapStatic(false)
				Expect(err).To(Succeed())
				ok = m.Match(nil)
			})
			It("returns false", func() {
				Expect(ok).To(BeFalse())
			})
		})
		When("invalid", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDnstapStatic(1)
			})
			It("returns false", func() {
				Expect(err).To(HaveOccurred())
			})
		})
	})
	Context("matchStaticDNSMsg", func() {
		var (
			err error
			m   matcher.DnsMsgMatcher
			ok  bool
		)
		When("true", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgStatic(true)
				Expect(err).To(Succeed())
				ok = m.Match(nil)
			})
			It("returns true", func() {
				Expect(ok).To(BeTrue())
			})
		})
		When("false", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgStatic(false)
				Expect(err).To(Succeed())
				ok = m.Match(nil)
			})
			It("returns false", func() {
				Expect(ok).To(BeFalse())
			})
		})
		When("invalid", func() {
			BeforeEach(func() {
				m, err = matcher.NewMatchDNSMsgStatic(1)
			})
			It("returns false", func() {
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
