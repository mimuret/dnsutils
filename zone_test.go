package dnsutils_test

import (
	"github.com/mimuret/dnsutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Zone", func() {
	Context("Test for GetName", func() {
		It("return canonical zone name", func() {
			z := dnsutils.NewZone("example.jp")
			Expect(z.GetName()).To(Equal("example.jp."))
		})
	})
	Context("Test for GetRootNode", func() {
		It("return root NameNode", func() {
			z := dnsutils.NewZone("example.jp")
			Expect(z.GetRootNode()).NotTo(BeNil())
			Expect(z.GetRootNode().GetName()).To(Equal("example.jp."))
		})
	})
})
