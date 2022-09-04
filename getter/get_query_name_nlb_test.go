package getter_test

import (
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QNameNLD", func() {
	var (
		successCases = []struct {
			Name   getter.DnsMsgGetterName
			Result string
		}{
			{
				"QnameTLD",
				"jp.",
			},
			{
				"Qname1LD",
				"jp.",
			},
			{
				"QnameSLD",
				"example.jp.",
			},
			{
				"Qname2LD",
				"example.jp.",
			},
			{
				"Qname3LD",
				"3.example.jp.",
			},
			{
				"Qname4LD",
				"4.3.example.jp.",
			},
			{
				"Qname5LD",
				"5.4.3.example.jp.",
			},
		}
	)
	Context("GetQNameNLDString", func() {
		var (
			s       string
			strFunc = getter.NewDnsMsgStrFunc("QnameTLD")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = strFunc(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("question is nil", func() {
			BeforeEach(func() {
				s = strFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("label is short", func() {
			BeforeEach(func() {
				strFunc = getter.NewDnsMsgStrFunc("Qname5LD")
				s = strFunc(&dns.Msg{Question: []dns.Question{{Name: "example.jp"}}})
			})
			It("returns FQDN", func() {
				Expect(s).To(Equal("example.jp."))
			})
		})
		When("valid msg", func() {
			It("success", func() {
				m := &dns.Msg{Question: []dns.Question{{Name: "7.6.5.4.3.example.jp"}}}
				for _, c := range successCases {
					getFunc := getter.NewDnsMsgStrFunc(c.Name)
					Expect(getFunc).NotTo(BeNil())
					s = getFunc(m)
					Expect(s).To(Equal(c.Result))
				}
			})
		})
	})
	Context("GetQNameTLD", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnsMsgGetFunc("QNameTLD")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getFunc(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("question is nil", func() {
			BeforeEach(func() {
				s = getFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(BeNil())
			})
		})
		When("valid msg", func() {
			It("success", func() {
				m := &dns.Msg{Question: []dns.Question{{Name: "7.6.5.4.3.example.jp"}}}
				for _, c := range successCases {
					getFunc := getter.NewDnsMsgGetFunc(c.Name)
					Expect(getFunc).NotTo(BeNil())
					s = getFunc(m)
					Expect(s).To(Equal(c.Result))
				}
			})
		})
	})
})
