package getter_test

import (
	_ "embed"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ResponsePort", func() {
	Context("GetResponsePortString", func() {
		var (
			s       string
			strFunc = getter.NewDnstapStrFunc("ResponsePort")
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = strFunc(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = strFunc(m)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid message", func() {
			BeforeEach(func() {
				p := uint32(10053)
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					ResponsePort: &p,
				}}
				s = strFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal("10053"))
			})
		})
	})
	Context("GetResponsePort", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnstapGetFunc("ResponsePort")
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = getFunc(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = getFunc(m)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("valid message", func() {
			BeforeEach(func() {
				p := uint32(10053)
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					ResponsePort: &p,
				}}
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(uint32(10053)))
			})
		})
	})
})
