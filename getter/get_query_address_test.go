package getter_test

import (
	_ "embed"
	"net"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QueryAddress", func() {
	Context("GetQueryAddressString", func() {
		var (
			s string
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = getter.GetQueryAddressString(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = getter.GetQueryAddressString(m)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("QueryAddress is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{Message: &dnstap.Message{}}
				s = getter.GetQueryAddressString(m)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid message", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					QueryAddress: net.IPv4(127, 0, 0, 1),
				}}
				s = getter.GetQueryAddressString(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal("127.0.0.1"))
			})
		})
	})
	Context("GetQueryAddress", func() {
		var (
			s interface{}
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = getter.GetQueryAddress(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = getter.GetQueryAddress(m)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("valid message", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					QueryAddress: net.IPv4(127, 0, 0, 1),
				}}
				s = getter.GetQueryAddress(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal([]byte(net.IPv4(127, 0, 0, 1))))
			})
		})
	})
})
