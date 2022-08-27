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
			s       string
			strFunc = getter.NewDnstapStrFunc("MessageFamily")
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
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					SocketFamily: dnstap.SocketFamily_INET6.Enum(),
				}}
				s = strFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(dnstap.SocketFamily_INET6.String()))
			})
		})
	})
	Context("GetSocketFamily", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnstapGetFunc("SocketFamily")
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
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					SocketFamily: dnstap.SocketFamily_INET6.Enum(),
				}}
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(dnstap.SocketFamily_INET6))
			})
		})
	})
})
