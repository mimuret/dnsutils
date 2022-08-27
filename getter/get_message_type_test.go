package getter_test

import (
	_ "embed"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SocketProtocol", func() {
	Context("GetMessageTypeString", func() {
		var (
			s       string
			strFunc = getter.NewDnstapStrFunc("MessageType")
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
					Type: dnstap.Message_AUTH_QUERY.Enum(),
				}}
				s = strFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(dnstap.Message_AUTH_QUERY.String()))
			})
		})
	})
	Context("GetMessageType", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnstapGetFunc("MessageType")
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
					Type: dnstap.Message_AUTH_QUERY.Enum(),
				}}
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(dnstap.Message_AUTH_QUERY))
			})
		})
	})
})
