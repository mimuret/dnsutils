package matcher_test

import (
	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("utils", func() {
	Context("GetBool", func() {
		When("bool", func() {
			It("returns self", func() {
				Expect(matcher.GetBool(true)).To(BeTrue())
				Expect(matcher.GetBool(false)).To(BeFalse())
			})
		})
		When("string", func() {
			It("returns self", func() {
				_, err := matcher.GetBool("true")
				Expect(err).To(HaveOccurred())
				_, err = matcher.GetBool("false")
				Expect(err).To(HaveOccurred())
				_, err = matcher.GetBool("hoge")
				Expect(err).To(HaveOccurred())
			})
		})
		When("int", func() {
			It("returns self", func() {
				_, err := matcher.GetBool(1)
				Expect(err).To(HaveOccurred())
				_, err = matcher.GetBool(1)
				Expect(err).To(HaveOccurred())
			})
		})
	})
	Context("UnmarshalBoolArg", func() {
		var (
			ok  interface{}
			err error
			bs  []byte
		)
		When("true", func() {
			BeforeEach(func() {
				bs = []byte("true")
				ok, err = matcher.UnmarshalBoolArg(bs)
			})
			It("returns true", func() {
				Expect(err).To(Succeed())
				Expect(ok).To(BeTrue())
			})
		})
		When("false", func() {
			BeforeEach(func() {
				bs = []byte("false")
				ok, err = matcher.UnmarshalBoolArg(bs)
			})
			It("returns false", func() {
				Expect(err).To(Succeed())
				Expect(ok).To(BeFalse())
			})
		})
		When("Other", func() {
			BeforeEach(func() {
				bs = []byte("False")
				ok, err = matcher.UnmarshalBoolArg(bs)
			})
			It("returns false", func() {
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
