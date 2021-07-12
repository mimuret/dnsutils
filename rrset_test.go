package dnsutils_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
)

var _ = Describe("RRSet", func() {
	var (
		a11    = MustNewRR("example.jp. 300 IN A 192.168.0.1")
		a12    = MustNewRR("example.jp. 300 IN A 192.168.0.2")
		soa1   = MustNewRR("example.jp. 300 IN SOA localhost. root.localhost. 1 3600 600 86400 900")
		soa2   = MustNewRR("example.jp. 300 IN SOA localhost. root.localhost. 2 3600 600 86400 900")
		cname1 = MustNewRR("example.jp. 300 IN CNAME www1.example.jp.")
		cname2 = MustNewRR("example.jp. 300 IN CNAME www2.example.jp.")
	)
	Context("test for GetName", func() {
		It("return canonical name", func() {
			rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, nil)
			Expect(rrset.GetName()).To(Equal("example.jp."))
		})
	})
	Context("test for GetType", func() {
		It("return uint16 rrtype", func() {
			rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, nil)
			Expect(rrset.GetRRtype()).To(Equal(dns.TypeA))
		})
	})
	Context("test for GetRRs", func() {
		It("return RR slice", func() {
			rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a11, a12})
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{a11, a12}))
		})
	})
	Context("test for AddRR (Normal)", func() {
		It("can be add uniq RR", func() {
			rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, nil)
			err := rrset.AddRR(a11)
			Expect(err).To(BeNil())
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{a11}))
			err = rrset.AddRR(a11)
			Expect(err).To(BeNil())
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{a11}))
			err = rrset.AddRR(a12)
			Expect(err).To(BeNil())
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{a11, a12}))
		})
	})
	Context("test for AddRR(SOA RR)", func() {
		It("can not be add multiple RR", func() {
			rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeSOA, []dns.RR{soa1})
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{soa1}))

			err := rrset.AddRR(soa2)
			Expect(err).NotTo(BeNil())
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{soa1}))
		})
	})
	Context("test for AddRR(CNAME RR)", func() {
		It("can not be add multiple RR", func() {
			rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeCNAME,
				[]dns.RR{cname1})
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{cname1}))

			err := rrset.AddRR(cname2)
			Expect(err).NotTo(BeNil())
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{cname1}))
		})
	})
})
