package getter_test

import (
	_ "embed"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SocketFamily", func() {
	Context("GetSocketFamilyString", func() {
		var (
			s string
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = getter.GetSocketFamilyString(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = getter.GetSocketFamilyString(m)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid message", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					SocketFamily: dnstap.SocketFamily_INET6.Enum(),
				}}
				s = getter.GetSocketFamilyString(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(dnstap.SocketFamily_INET6.String()))
			})
		})
	})
	Context("GetSocketFamily", func() {
		var (
			s interface{}
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = getter.GetSocketFamily(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = getter.GetSocketFamily(m)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("valid message", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					SocketFamily: dnstap.SocketFamily_INET6.Enum(),
				}}
				s = getter.GetSocketFamily(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(dnstap.SocketFamily_INET6))
			})
		})
	})
})
