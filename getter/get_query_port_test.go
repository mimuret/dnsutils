package getter_test

import (
	_ "embed"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QueryPort", func() {
	Context("GetQueryPortString", func() {
		var (
			s string
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = getter.GetQueryPortString(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = getter.GetQueryPortString(m)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid message", func() {
			BeforeEach(func() {
				p := uint32(10053)
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					QueryPort: &p,
				}}
				s = getter.GetQueryPortString(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal("10053"))
			})
		})
	})
	Context("GetQueryPort", func() {
		var (
			s interface{}
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = getter.GetQueryPort(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = getter.GetQueryPort(m)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("valid message", func() {
			BeforeEach(func() {
				p := uint32(10053)
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					QueryPort: &p,
				}}
				s = getter.GetQueryPort(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(uint32(10053)))
			})
		})
	})
})
