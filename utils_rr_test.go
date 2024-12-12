package dnsutils_test

import (
	"github.com/mimuret/dnsutils"
	. "github.com/mimuret/dnsutils/testtool"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("utils", func() {
	var (
		res int
		err error
	)
	Context("CompareRR", func() {
		When("same name,type,rdata", func() {
			BeforeEach(func() {
				a1 := MustNewRR("example.jp. 300 IN A 192.168.0.1")
				a2 := MustNewRR("example.jp. 300 IN A 192.168.0.1")
				res, err = dnsutils.CompareRR(a1, a2)
			})
			It("returnes 0", func() {
				Expect(err).To(Succeed())
				Expect(res).To(Equal(0))
			})
		})
		When("same name,type", func() {
			When("a radata < b radata", func() {
				BeforeEach(func() {
					a1 := MustNewRR("example.jp. 300 IN A 192.168.0.1")
					a2 := MustNewRR("example.jp. 300 IN A 192.168.0.2")
					res, err = dnsutils.CompareRR(a1, a2)
				})
				It("returnes -1", func() {
					Expect(err).To(Succeed())
					Expect(res).To(Equal(-1))
				})
			})
			When("a rdata > b rdata", func() {
				BeforeEach(func() {
					a1 := MustNewRR("example.jp. 300 IN A 192.168.0.2")
					a2 := MustNewRR("example.jp. 300 IN A 192.168.0.1")
					res, err = dnsutils.CompareRR(a1, a2)
				})
				It("returnes 1", func() {
					Expect(err).To(Succeed())
					Expect(res).To(Equal(1))
				})
			})
		})
		When("same name", func() {
			When("a rrtype < b rrtype ", func() {
				BeforeEach(func() {
					a1 := MustNewRR("example.jp. 300 IN A 192.168.0.1")
					a2 := MustNewRR("example.jp. 300 IN AAAA 2001:db8::1")
					res, err = dnsutils.CompareRR(a1, a2)
				})
				It("returnes -1", func() {
					Expect(err).To(Succeed())
					Expect(res).To(Equal(-1))
				})
			})
			When("a rrtype > b rrtype ", func() {
				BeforeEach(func() {
					a1 := MustNewRR("example.jp. 300 IN AAAA 2001:db8::1")
					a2 := MustNewRR("example.jp. 300 IN A 192.168.0.1")
					res, err = dnsutils.CompareRR(a1, a2)
				})
				It("returnes 1", func() {
					Expect(err).To(Succeed())
					Expect(res).To(Equal(1))
				})
			})
		})
		When("different name", func() {
			When("a name < b name ", func() {
				BeforeEach(func() {
					a1 := MustNewRR("example.jp. 300 IN A 192.168.0.1")
					a2 := MustNewRR("a.example.jp. 300 IN A 192.168.0.1")
					res, err = dnsutils.CompareRR(a1, a2)
				})
				It("returnes -1", func() {
					Expect(err).To(Succeed())
					Expect(res).To(Equal(-1))
				})
			})
			When("a rrtype > b rrtype ", func() {
				BeforeEach(func() {
					a1 := MustNewRR("a.example.jp. 300 IN A 192.168.0.1")
					a2 := MustNewRR("example.jp. 300 IN A 192.168.0.1")
					res, err = dnsutils.CompareRR(a1, a2)
				})
				It("returnes 1", func() {
					Expect(err).To(Succeed())
					Expect(res).To(Equal(1))
				})
			})
		})
	})
})
