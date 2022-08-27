package getter_test

import (
	_ "embed"
	"net"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ResponseAddress", func() {
	Context("GetResponseAddressString", func() {
		var (
			s string
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = getter.GetResponseAddressString(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = getter.GetResponseAddressString(m)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("ResponseAddress is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{Message: &dnstap.Message{}}
				s = getter.GetResponseAddressString(m)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid message", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					ResponseAddress: net.IPv4(127, 0, 0, 1),
				}}
				s = getter.GetResponseAddressString(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal("127.0.0.1"))
			})
		})
	})
	Context("GetResponseAddress", func() {
		var (
			s interface{}
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = getter.GetResponseAddress(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = getter.GetResponseAddress(m)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("valid message", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{Message: &dnstap.Message{
					ResponseAddress: net.IPv4(127, 0, 0, 1),
				}}
				s = getter.GetResponseAddress(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal([]byte(net.IPv4(127, 0, 0, 1))))
			})
		})
	})
})
