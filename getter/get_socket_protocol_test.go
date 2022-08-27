package getter_test

import (
	_ "embed"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MessageType", func() {
	Context("GetMessageTypeString", func() {
		var (
			s string
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = getter.GetMessageTypeString(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = getter.GetMessageTypeString(m)
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
				s = getter.GetMessageTypeString(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(dnstap.Message_AUTH_QUERY.String()))
			})
		})
	})
	Context("GetMessageType", func() {
		var (
			s interface{}
		)
		When("dnstap is nil", func() {
			BeforeEach(func() {
				s = getter.GetMessageType(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("message is nil", func() {
			BeforeEach(func() {
				m := &dnstap.Dnstap{}
				s = getter.GetMessageType(m)
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
				s = getter.GetMessageType(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(dnstap.Message_AUTH_QUERY))
			})
		})
	})
})
