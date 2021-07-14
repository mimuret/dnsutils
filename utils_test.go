package dnsutils_test

import (
	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
	. "github.com/mimuret/dnsutils/testtool"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("utils", func() {
	var (
		soa = MustNewRR("example.jp. 300 IN SOA localhost. root.localhost. 1 3600 600 86400 900")
		a1  = MustNewRR("example.jp. 300 IN A 192.168.0.1")
		a2  = MustNewRR("example.jp. 300 IN A 192.168.0.2")
		www = MustNewRR("www.example.jp. 300 IN A 192.168.0.1")
	)
	Context("Test for Equals", func() {
		It("can compare between non-normalized name", func() {
			testcases := []struct {
				A   string
				B   string
				res OmegaMatcher
			}{
				{
					"example.jp.", "example.jp.", BeTrue(),
				},
				{
					"example.jp.", "example.jp", BeTrue(),
				},
				{
					"Example.jp.", "example.Jp", BeTrue(),
				},
				{
					"Example.j2p.", "example.Jp", BeFalse(),
				},
				{
					".example.jp.", "example.jp.", BeFalse(),
				},
				{
					"jp.", "example.jp.", BeFalse(),
				},
				{
					"example.jp.", "jp.", BeFalse(),
				},
			}
			for _, tc := range testcases {
				res := dnsutils.Equals(tc.A, tc.B)
				Expect(res).To(tc.res)
			}
		})
	})
	Context("IsENT", func() {
		When("rrset exist and rdata exist", func() {
			It("returns false", func() {
				a := MustNewRR("example.jp. 300 IN A 192.168.0.1")
				n := dnsutils.NewNameNode("example.jp", dns.ClassINET)
				n.SetRRSet(dnsutils.NewRRSetFromRR(a))
				Expect(dnsutils.IsENT(n)).To(BeFalse())
			})
		})
		When("rrset exist and rdata not exist", func() {
			It("returns true", func() {
				n := dnsutils.NewNameNode("example.jp", dns.ClassINET)
				n.SetRRSet(dnsutils.NewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, nil))
				Expect(dnsutils.IsENT(n)).To(BeTrue())
			})
		})
		When("rrset not exist", func() {
			It("returns true", func() {
				n := dnsutils.NewNameNode("example.jp", dns.ClassINET)
				Expect(dnsutils.IsENT(n)).To(BeTrue())
			})
		})
	})
	Context("IsEqualsRRSet", func() {
		When("ignore name", func() {
			It("returns false", func() {
				a := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, nil)
				b := dnsutils.NewRRSet("example.jp2", 300, dns.ClassINET, dns.TypeA, nil)
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeFalse())
			})
		})
		When("ignore type", func() {
			It("returns false", func() {
				a := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, nil)
				b := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeAAAA, nil)
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeFalse())
			})
		})
		When("ignore rdata length", func() {
			It("returns false", func() {
				a := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a2})
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeFalse())
			})
		})
		When("ignore rdata", func() {
			It("returns false", func() {
				a := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1})
				b := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a2})
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeFalse())
			})
		})
		When("same (rdata is particular order)", func() {
			It("returns true", func() {
				a := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeTrue())
			})
		})
		When("same (rdata is no particular order)", func() {
			It("returns true", func() {
				a := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a2, a1})
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeTrue())
			})
		})
		When("same (ttl is ignore)", func() {
			It("returns true", func() {
				a := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := dnsutils.NewRRSet("example.jp", 100, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeTrue())
			})
		})
	})
	Context("IsCompleteEqualsRRSet", func() {
		When("ttl is ignore", func() {
			It("returns false", func() {
				a := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := dnsutils.NewRRSet("example.jp", 100, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				Expect(dnsutils.IsCompleteEqualsRRSet(a, b)).To(BeFalse())
			})
		})
		When("same", func() {
			It("returns false", func() {
				a := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				Expect(dnsutils.IsCompleteEqualsRRSet(a, b)).To(BeTrue())
			})
		})
	})
	Context("IsEmptyRRSet", func() {
		When("set is nil", func() {
			It("returns true", func() {
				Expect(dnsutils.IsEmptyRRSet(nil)).To(BeTrue())
			})
		})
		When("set is not nil, rdata is empty", func() {
			It("returns true", func() {
				set := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, nil)
				Expect(dnsutils.IsEmptyRRSet(set)).To(BeTrue())
			})
		})
		When("set is not nil, rdata is not empty", func() {
			It("returns false", func() {
				set := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1})
				Expect(dnsutils.IsEmptyRRSet(set)).To(BeFalse())
			})
		})
	})
	Context("GetRRSetOrCreate", func() {
		When("exist rrset", func() {
			It("returns existing　rrset", func() {
				set := dnsutils.NewRRSetFromRRs([]dns.RR{a1, a2})
				root := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				root.SetRRSet(set)
				Expect(dnsutils.GetRRSetOrCreate(root, dns.TypeA, 300)).To(Equal(set))
			})
		})
		When("not exist rrset", func() {
			It("returns new rrset", func() {
				root := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				a4set := dnsutils.GetRRSetOrCreate(root, dns.TypeAAAA, 300)
				Expect(a4set.GetRRtype()).To(Equal(dns.TypeAAAA))
				Expect(a4set.GetName()).To(Equal("example.jp."))
			})
		})
	})
	Context("GetNodeOrCreate", func() {
		When("exist node", func() {
			It("returns existing node", func() {
				set := dnsutils.NewRRSetFromRR(www)
				root := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				wwwNode := dnsutils.NewNameNode("www.example.jp.", dns.ClassINET)
				wwwNode.SetRRSet(set)
				root.SetNameNode(wwwNode)
				Expect(dnsutils.GetNameNodeOrCreate(root, "www.example.jp")).To(Equal(wwwNode))
			})
		})
		When("not exist node", func() {
			It("returns new node", func() {
				root := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				wwwNode := dnsutils.GetNameNodeOrCreate(root, "www.example.jp")
				Expect(wwwNode.GetName()).To(Equal("www.example.jp."))
			})
		})
	})
	Context("GetRDATA", func() {
		When("rdata exist", func() {
			It("returns rdata", func() {
				Expect(dnsutils.GetRDATA(a1)).To(Equal("192.168.0.1"))
				Expect(dnsutils.GetRDATA(soa)).To(Equal("localhost. root.localhost. 1 3600 600 86400 900"))
			})
		})
		When("rdata not exist", func() {
			It("returns empty", func() {
				any := &dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeMAILA, Class: dns.ClassINET, Rdlength: 0}}
				Expect(dnsutils.GetRDATA(any)).To(Equal(""))
			})
		})
	})
	Context("MakeRR", func() {
		It("returns RR", func() {
			set := dnsutils.NewRRSetFromRR(a1)
			arr, err := dnsutils.MakeRR(set, "192.168.0.2")
			Expect(err).To(BeNil())
			Expect(arr).To(Equal(a2))
		})
	})
})
