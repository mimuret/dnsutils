package getter_test

import (
	_ "embed"
	"fmt"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QNameNLD", func() {
	Context("GetQNameNLDString", func() {
		var (
			s            string
			strFunc      = getter.NewDnsMsgStrFunc("QnameTLD")
			successCases = []struct {
				Getter getter.DnsMsgStrFunc
				Result string
			}{
				{
					getter.NewDnsMsgStrFunc("QnameTLD"),
					"jp.",
				},
				{
					getter.NewDnsMsgStrFunc("Qname1LD"),
					"jp.",
				},
				{
					getter.NewDnsMsgStrFunc("QnameSLD"),
					"example.jp.",
				},
				{
					getter.NewDnsMsgStrFunc("Qname2LD"),
					"example.jp.",
				},
				{
					getter.NewDnsMsgStrFunc("Qname3LD"),
					"3.example.jp.",
				},
				{
					getter.NewDnsMsgStrFunc("Qname4LD"),
					"4.3.example.jp.",
				},
				{
					getter.NewDnsMsgStrFunc("Qname5LD"),
					"5.4.3.example.jp.",
				},
			}
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
		When("valid msg", func() {
			It("success", func() {
				m := &dns.Msg{Question: []dns.Question{{Name: "7.6.5.4.3.example.jp"}}}
				for _, c := range successCases {
					s = c.Getter(m)
					fmt.Println(s)
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
		When("msg is not nil", func() {
			BeforeEach(func() {
				m := &dns.Msg{Question: []dns.Question{{Name: "7.6.5.4.3.example.jp"}}}
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal("jp."))
			})
		})
	})
})
