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
			s       string
			strFunc = getter.NewDnstapStrFunc("ResponseAddress")
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
		When("ResponseAddress is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{Message: &dnstap.Message{}}
				s = strFunc(m)
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
				s = strFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal("127.0.0.1"))
			})
		})
	})
	Context("GetResponseAddress", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnstapGetFunc("ResponseAddress")
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
					ResponseAddress: net.IPv4(127, 0, 0, 1),
				}}
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal([]byte(net.IPv4(127, 0, 0, 1))))
			})
		})
	})
})
