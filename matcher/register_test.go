package matcher_test

import (
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("register", func() {
	Context("RegisterDnstapMatcher", func() {
		When("name is empty", func() {
			It("raise panic", func() {
				Expect(func() { matcher.RegisterDnstapMatcher("", matcher.NewMatchDnstapStatic, matcher.UnmarshalBoolArg) }).To(Panic())
			})
		})
		When("newFunc is nil", func() {
			It("raise panic", func() {
				Expect(func() { matcher.RegisterDnstapMatcher("test", nil, matcher.UnmarshalBoolArg) }).To(Panic())
			})
		})
		When("newFunc is nilValue", func() {
			It("raise panic", func() {
				var newFunc matcher.NewDnstapMatcher
				Expect(func() { matcher.RegisterDnstapMatcher("test", newFunc, matcher.UnmarshalBoolArg) }).To(Panic())
			})
		})
		When("unmarshaler is nil", func() {
			It("raise panic", func() {
				Expect(func() { matcher.RegisterDnstapMatcher("test", matcher.NewMatchDnstapStatic, nil) }).To(Panic())
			})
		})
		When("unmarshaler is nilValue", func() {
			It("raise panic", func() {
				var unmarshaler matcher.UnmarshalFunc
				Expect(func() { matcher.RegisterDnstapMatcher("test", matcher.NewMatchDnstapStatic, unmarshaler) }).To(Panic())
			})
		})
		When("vaild args", func() {
			It("no raise panic", func() {
				Expect(func() { matcher.RegisterDnstapMatcher("test", matcher.NewMatchDnstapStatic, matcher.UnmarshalBoolArg) }).NotTo(Panic())
			})
		})
	})
	Context("RegisterDnsMsgMatcher", func() {
		When("name is empty", func() {
			It("raise panic", func() {
				Expect(func() { matcher.RegisterDnsMsgMatcher("", matcher.NewMatchDNSMsgStatic, matcher.UnmarshalBoolArg) }).To(Panic())
			})
		})
		When("newFunc is nil", func() {
			It("raise panic", func() {
				Expect(func() { matcher.RegisterDnsMsgMatcher("test", nil, matcher.UnmarshalBoolArg) }).To(Panic())
			})
		})
		When("newFunc is nilValue", func() {
			It("raise panic", func() {
				var newFunc matcher.NewDnsMsgMatcher
				Expect(func() { matcher.RegisterDnsMsgMatcher("test", newFunc, matcher.UnmarshalBoolArg) }).To(Panic())
			})
		})
		When("unmarshaler is nil", func() {
			It("raise panic", func() {
				Expect(func() { matcher.RegisterDnsMsgMatcher("test", matcher.NewMatchDNSMsgStatic, nil) }).To(Panic())
			})
		})
		When("unmarshaler is nilValue", func() {
			It("raise panic", func() {
				var unmarshaler matcher.UnmarshalFunc
				Expect(func() { matcher.RegisterDnsMsgMatcher("test", matcher.NewMatchDNSMsgStatic, unmarshaler) }).To(Panic())
			})
		})
		When("vaild args", func() {
			It("no raise panic", func() {
				Expect(func() { matcher.RegisterDnsMsgMatcher("test", matcher.NewMatchDNSMsgStatic, matcher.UnmarshalBoolArg) }).NotTo(Panic())
			})
		})
	})
})
