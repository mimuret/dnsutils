package dnsutils_test

import (
	"fmt"
	"math"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
	. "github.com/mimuret/dnsutils/testtool"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ dnsutils.NameNodeInterface = &BrokenNode{}

type BrokenNode struct {
	*dnsutils.NameNode
	Children map[string]dnsutils.NameNodeInterface
}

func (n *BrokenNode) GetNameNode(target string) (node dnsutils.NameNodeInterface, isStrict bool) {
	nn, ok := n.Children[dns.CanonicalName(target)]
	return nn, ok
}

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
					"\x45xample.jp.", "example.jp.", BeTrue(),
				},
				{
					"\x65xample.jp.", "example.jp.", BeTrue(),
				},
				{
					"\105xample.jp.", "example.jp.", BeTrue(),
				},
				{
					"\145xample.jp.", "example.jp.", BeTrue(),
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
				{
					"..", ".", BeFalse(),
				},
				{
					".", "..", BeFalse(),
				},
			}
			for _, tc := range testcases {
				res := dnsutils.Equals(tc.A, tc.B)
				Expect(res).To(tc.res)
			}
		})
	})
	Context("Test for IsHostname", func() {
		var (
			name     string
			idDomain bool
			isHost   bool
		)
		When("invalid domain name", func() {
			BeforeEach(func() {
				name = ".."
				_, idDomain = dns.IsDomainName(name)
				isHost = dnsutils.IsHostname(name)
			})
			It("returns false", func() {
				Expect(idDomain).To(BeFalse())
				Expect(isHost).To(BeFalse())
			})
		})
		When("invalid hostname name", func() {
			It("returns false", func() {
				testcase := []string{
					"_dmarc.example.jp",
					"a-.example.jp.",
					"-.example.jp.",
					"-a.example.jp.",
					"_.example.jp.",
					"a_b.example.jp.",
				}
				for _, tc := range testcase {
					_, idDomain = dns.IsDomainName(tc)
					isHost = dnsutils.IsHostname(tc)
					Expect(idDomain).To(BeTrue(), tc)
					Expect(isHost).To(BeFalse(), tc)
				}
			})
		})
		When("wiledcard name", func() {
			BeforeEach(func() {
				name = "*.example.jp"
				_, idDomain = dns.IsDomainName(name)
				isHost = dnsutils.IsHostname(name)
			})
			It("returns false", func() {
				Expect(idDomain).To(BeTrue())
				Expect(isHost).To(BeFalse())
			})
		})
		When("valid hostname name", func() {
			It("returns true", func() {
				testcase := []string{
					"1.example.jp.",
					"a.example.jp.",
					"\101.example.jp.",
					"\x65.example.jp.",
					"1B.example.jp.",
					"1-B.example.jp.",
					"1-C.example.jp.",
				}
				for _, tc := range testcase {
					_, idDomain = dns.IsDomainName(tc)
					isHost = dnsutils.IsHostname(tc)
					Expect(idDomain).To(BeTrue(), tc)
					Expect(isHost).To(BeTrue(), tc)
				}
			})
		})
	})
	Context("IsENT", func() {
		When("rrset exist and rdata exist", func() {
			It("returns false", func() {
				a := MustNewRR("example.jp. 300 IN A 192.168.0.1")
				n := MustNewNameNode("example.jp", dns.ClassINET)
				n.SetRRSet(dnsutils.NewRRSetFromRR(a))
				Expect(dnsutils.IsENT(n)).To(BeFalse())
			})
		})
		When("rrset exist and rdata not exist", func() {
			It("returns true", func() {
				n := MustNewNameNode("example.jp", dns.ClassINET)
				set := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, nil)
				n.SetRRSet(set)
				Expect(dnsutils.IsENT(n)).To(BeTrue())
			})
		})
		When("rrset not exist", func() {
			It("returns true", func() {
				n := MustNewNameNode("example.jp", dns.ClassINET)
				Expect(dnsutils.IsENT(n)).To(BeTrue())
			})
		})
	})
	Context("IsEqualsRRSet", func() {
		When("ignore name", func() {
			It("returns false", func() {
				a := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, nil)
				b := MustNewRRSet("example.jp2", 300, dns.ClassINET, dns.TypeA, nil)
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeFalse())
			})
		})
		When("ignore type", func() {
			It("returns false", func() {
				a := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, nil)
				b := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeAAAA, nil)
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeFalse())
			})
		})
		When("ignore rdata length", func() {
			It("returns false", func() {
				a := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a2})
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeFalse())
			})
		})
		When("ignore rdata", func() {
			It("returns false", func() {
				a := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1})
				b := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a2})
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeFalse())
			})
		})
		When("same (rdata is particular order)", func() {
			It("returns true", func() {
				a := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeTrue())
			})
		})
		When("same (rdata is no particular order)", func() {
			It("returns true", func() {
				a := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a2, a1})
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeTrue())
			})
		})
		When("same (ttl is ignore)", func() {
			It("returns true", func() {
				a := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := MustNewRRSet("example.jp.", 100, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				Expect(dnsutils.IsEqualsRRSet(a, b)).To(BeTrue())
			})
		})
	})
	Context("IsCompleteEqualsRRSet", func() {
		When("ttl is ignore", func() {
			It("returns false", func() {
				a := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := MustNewRRSet("example.jp.", 100, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				Expect(dnsutils.IsCompleteEqualsRRSet(a, b)).To(BeFalse())
			})
		})
		When("same", func() {
			It("returns false", func() {
				a := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				b := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1, a2})
				Expect(dnsutils.IsCompleteEqualsRRSet(a, b)).To(BeTrue())
			})
		})
	})
	Context("IsEqualsNode", func() {
		var (
			a, b *dnsutils.NameNode
			ok   bool
		)
		When("equls empty node", func() {
			BeforeEach(func() {
				a = MustNewNameNode("example.jp.", dns.ClassINET)
				b = MustNewNameNode("example.jp.", dns.ClassINET)
				ok = dnsutils.IsEqualsNode(a, b, false)
			})
			It("returns true", func() {
				Expect(ok).To(BeTrue())
			})
		})
		When("equls node", func() {
			BeforeEach(func() {
				a = MustNewNameNode("example.jp.", dns.ClassINET)
				a.SetRRSet(MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeSOA, []dns.RR{MustNewRR("example.jp. 3600 IN SOA localhost. root.localhost. 1 3600 900 85400 300")}))
				a.SetRRSet(MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeNS, []dns.RR{MustNewRR("example.jp. 3600 IN NS ns.example.com.")}))

				b = MustNewNameNode("example.jp.", dns.ClassINET)
				b.SetRRSet(MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeSOA, []dns.RR{MustNewRR("example.jp. 3600 IN SOA localhost. root.localhost. 1 3600 900 85400 300")}))
				b.SetRRSet(MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeNS, []dns.RR{MustNewRR("example.jp. 3600 IN NS ns.example.com.")}))
			})
			It("returns true", func() {
				ok = dnsutils.IsEqualsNode(a, b, false)
				Expect(ok).To(BeTrue())
				ok = dnsutils.IsEqualsNode(a, b, true)
				Expect(ok).To(BeTrue())
			})
		})
		When("a has more rrset", func() {
			BeforeEach(func() {
				a = MustNewNameNode("example.jp.", dns.ClassINET)
				a.SetRRSet(MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeSOA, []dns.RR{MustNewRR("example.jp. 3600 IN SOA localhost. root.localhost. 1 3600 900 85400 300")}))
				a.SetRRSet(MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeNS, []dns.RR{MustNewRR("example.jp. 3600 IN NS ns.example.com.")}))

				b = MustNewNameNode("example.jp.", dns.ClassINET)
				b.SetRRSet(MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeSOA, []dns.RR{MustNewRR("example.jp. 3600 IN SOA localhost. root.localhost. 1 3600 900 85400 300")}))
			})
			It("returns false", func() {
				ok = dnsutils.IsEqualsNode(a, b, false)
				Expect(ok).To(BeFalse())
				ok = dnsutils.IsEqualsNode(a, b, true)
				Expect(ok).To(BeFalse())
			})
		})
		When("name ignore", func() {
			BeforeEach(func() {
				a = MustNewNameNode("example.jp.", dns.ClassINET)
				b = MustNewNameNode("example.com.", dns.ClassINET)
				ok = dnsutils.IsEqualsNode(a, b, false)
			})
			It("returns false", func() {
				Expect(ok).To(BeFalse())
			})
		})
		When("rrset ignore", func() {
			BeforeEach(func() {
				a = MustNewNameNode("example.jp.", dns.ClassINET)
				a.SetRRSet(MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeSOA, []dns.RR{MustNewRR("example.jp. 3600 IN SOA localhost. root.localhost. 1 3600 900 85400 300")}))
				a.SetRRSet(MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeNS, []dns.RR{MustNewRR("example.jp. 3600 IN NS ns.example.com.")}))
				b = MustNewNameNode("example.jp.", dns.ClassINET)
				b.SetRRSet(MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeSOA, []dns.RR{MustNewRR("example.jp. 3600 IN SOA localhost. root.localhost. 1 3600 900 85400 300")}))
				b.SetRRSet(MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeNS, []dns.RR{MustNewRR("example.jp. 3600 IN NS ns.example.net.")}))
			})
			It("returns false", func() {
				ok = dnsutils.IsEqualsNode(a, b, false)
				Expect(ok).To(BeFalse())
				ok = dnsutils.IsEqualsNode(a, b, true)
				Expect(ok).To(BeFalse())
			})
		})
	})
	Context("IsEqualsAllTree", func() {
		var (
			a, b     *dnsutils.NameNode
			ok       bool
			err      error
			soaRRSet = MustNewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeSOA, []dns.RR{MustNewRR("example.jp. 3600 IN SOA localhost. root.localhost. 1 3600 900 85400 300")})
			wwwRRSet = MustNewRRSet("www.sub.example.jp.", 3600, dns.ClassINET, dns.TypeA, []dns.RR{MustNewRR("www.sub.exmaple.jp. 3600 IN A 192.168.0.0")})
			mxRRSet  = MustNewRRSet("mx.sub.example.jp.", 3600, dns.ClassINET, dns.TypeMX, []dns.RR{MustNewRR("mx.sub.exmaple.jp. 3600 IN MX 0 mx.example.com.")})

			txtRRSet  = MustNewRRSet("txt.example.jp.", 3600, dns.ClassINET, dns.TypeTXT, []dns.RR{MustNewRR("txt.exmaple.jp. 3600 IN TXT \"hoge\"")})
			www6RRSet = MustNewRRSet("www.sub.example.jp.", 3600, dns.ClassINET, dns.TypeAAAA, []dns.RR{MustNewRR("www.sub.exmaple.jp. 3600 IN AAAA 2001:db8::1")})
		)
		BeforeEach(func() {
			a = MustNewNameNode("example.jp.", dns.ClassINET)
			a.SetRRSet(soaRRSet)
			mxNode := MustNewNameNode("mx.sub.example.jp.", dns.ClassINET)
			mxNode.SetRRSet(mxRRSet)
			err = dnsutils.SetNameNode(a, mxNode, nil)
			Expect(err).To(Succeed())
			wwwNode := MustNewNameNode("www.sub.example.jp.", dns.ClassINET)
			wwwNode.SetRRSet(wwwRRSet)
			err = dnsutils.SetNameNode(a, wwwNode, nil)
			Expect(err).To(Succeed())
		})
		When("equsls tree", func() {
			BeforeEach(func() {
				ok = dnsutils.IsEqualsAllTree(a, a, false)
			})
			It("returns true", func() {
				Expect(ok).To(BeTrue())
			})
		})
		When("root node name ignore", func() {
			BeforeEach(func() {
				a = MustNewNameNode("example.jp.", dns.ClassINET)
				b = MustNewNameNode("example.com.", dns.ClassINET)
				ok = dnsutils.IsEqualsAllTree(a, b, false)
			})
			It("returns false", func() {
				Expect(ok).To(BeFalse())
			})
		})
		When("a have more subdomain node", func() {
			BeforeEach(func() {
				b = MustNewNameNode("example.jp.", dns.ClassINET)
				b.SetRRSet(soaRRSet)
				ok = dnsutils.IsEqualsAllTree(a, b, false)
			})
			It("returns false", func() {
				Expect(ok).To(BeFalse())
			})
		})
		When("a have more node", func() {
			BeforeEach(func() {
				b = MustNewNameNode("example.jp.", dns.ClassINET)
				b.SetRRSet(soaRRSet)
				mxNode := MustNewNameNode("mx.sub.example.jp.", dns.ClassINET)
				mxNode.SetRRSet(mxRRSet)
				err = dnsutils.SetNameNode(b, mxNode, nil)
				Expect(err).To(Succeed())
				ok = dnsutils.IsEqualsAllTree(a, b, false)
			})
			It("returns false", func() {
				Expect(ok).To(BeFalse())
			})
		})
		When("b have more node", func() {
			BeforeEach(func() {
				b = MustNewNameNode("example.jp.", dns.ClassINET)
				b.SetRRSet(soaRRSet)
				mxNode := MustNewNameNode("mx.sub.example.jp.", dns.ClassINET)
				mxNode.SetRRSet(mxRRSet)
				err = dnsutils.SetNameNode(b, mxNode, nil)
				Expect(err).To(Succeed())
				wwwNode := MustNewNameNode("www.sub.example.jp.", dns.ClassINET)
				wwwNode.SetRRSet(wwwRRSet)
				err = dnsutils.SetNameNode(b, wwwNode, nil)
				Expect(err).To(Succeed())
				txtNode := MustNewNameNode("txt.example.jp.", dns.ClassINET)
				txtNode.SetRRSet(txtRRSet)
				err = dnsutils.SetNameNode(b, txtNode, nil)
				Expect(err).To(Succeed())
				ok = dnsutils.IsEqualsAllTree(a, b, true)
			})
			It("returns false", func() {
				Expect(ok).To(BeFalse())
			})
		})
		When("ignore node", func() {
			BeforeEach(func() {
				b = MustNewNameNode("example.jp.", dns.ClassINET)
				b.SetRRSet(soaRRSet)
				mxNode := MustNewNameNode("mx.sub.example.jp.", dns.ClassINET)
				mxNode.SetRRSet(mxRRSet)
				err = dnsutils.SetNameNode(b, mxNode, nil)
				Expect(err).To(Succeed())
				wwwNode := MustNewNameNode("www.sub.example.jp.", dns.ClassINET)
				wwwNode.SetRRSet(wwwRRSet)
				wwwNode.SetRRSet(www6RRSet)
				err = dnsutils.SetNameNode(b, wwwNode, nil)
				Expect(err).To(Succeed())
				ok = dnsutils.IsEqualsAllTree(a, b, true)
			})
			It("returns false", func() {
				Expect(ok).To(BeFalse())
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
				set := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, nil)
				Expect(dnsutils.IsEmptyRRSet(set)).To(BeTrue())
			})
		})
		When("set is not nil, rdata is not empty", func() {
			It("returns false", func() {
				set := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{a1})
				Expect(dnsutils.IsEmptyRRSet(set)).To(BeFalse())
			})
		})
	})
	Context("GetRRSetOrCreate", func() {
		When("exist rrset", func() {
			It("returns existing　rrset", func() {
				set := dnsutils.NewRRSetFromRRs([]dns.RR{a1, a2})
				root, err := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				Expect(err).To(Succeed())
				root.SetRRSet(set)
				Expect(dnsutils.GetRRSetOrCreate(root, dns.TypeA, 300, nil)).To(Equal(set))
			})
		})
		When("not exist rrset", func() {
			It("returns new rrset", func() {
				root, err := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				Expect(err).To(Succeed())
				a4set, _ := dnsutils.GetRRSetOrCreate(root, dns.TypeAAAA, 300, nil)
				Expect(a4set.GetRRtype()).To(Equal(dns.TypeAAAA))
				Expect(a4set.GetName()).To(Equal("example.jp."))
			})
		})
	})
	Context("GetNodeOrCreate", func() {
		When("invalid name ", func() {
			It("returns ErrBadName", func() {
				root := MustNewNameNode("example.jp.", dns.ClassINET)
				_, err := dnsutils.GetNameNodeOrCreate(root, "..www.example.jp", nil)
				Expect(err).To(Equal(dnsutils.ErrBadName))
			})
		})
		When("not name node subdomain or same domain", func() {
			It("returns ErrNotInDomain", func() {
				root := MustNewNameNode("example.jp.", dns.ClassINET)
				_, err := dnsutils.GetNameNodeOrCreate(root, "example.com", nil)
				Expect(err).To(Equal(dnsutils.ErrNotInDomain))
			})
		})
		When("exist node", func() {
			It("returns existing node", func() {
				set := dnsutils.NewRRSetFromRR(www)
				root, err := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				Expect(err).To(Succeed())
				wwwNode, err := dnsutils.NewNameNode("www.example.jp.", dns.ClassINET)
				Expect(err).To(Succeed())
				wwwNode.SetRRSet(set)
				dnsutils.SetNameNode(root, wwwNode, nil)
				Expect(dnsutils.GetNameNodeOrCreate(root, "www.example.jp", nil)).To(Equal(wwwNode))
			})
		})
		When("not exist node", func() {
			It("returns new node", func() {
				root, err := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				Expect(err).To(Succeed())
				wwwNode, err := dnsutils.GetNameNodeOrCreate(root, "www.example.jp", nil)
				Expect(err).To(Succeed())
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
			Expect(err).To(Succeed())
			Expect(arr).To(Equal(a2))
		})
	})
	Context("GetRDATASlice", func() {
		It("returns RDATA slice", func() {
			set := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{
				MustNewRR("example.jp. 300 IN A 192.168.0.1"),
				MustNewRR("example.jp. 300 IN A 192.168.0.2"),
			})
			Expect(dnsutils.GetRDATASlice(set)).To(Equal([]string{"192.168.0.1", "192.168.0.2"}))
		})
	})
	Context("SetRdata", func() {
		var (
			set *dnsutils.RRSet
			err error
		)
		BeforeEach(func() {
			set, _ = dnsutils.NewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, nil)
		})
		When("rdata is invalid", func() {
			BeforeEach(func() {
				err = dnsutils.SetRdata(set, []string{"192.168.0.1", "0000"})
			})
			It("returns ErrRdata", func() {
				Expect(err).To(Equal(dnsutils.ErrRdata))
			})
			It("nothing todo", func() {
				Expect(set.Len()).To(Equal(0))
			})
		})
		When("rdata is valid, but failed to AddRR", func() {
			BeforeEach(func() {
				set, _ = dnsutils.NewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeCNAME, nil)
				err = dnsutils.SetRdata(set, []string{"www.exampe.jp.", "www2.example.jp."})
			})
			It("returns ErrRdata", func() {
				Expect(err).To(Equal(dnsutils.ErrConflict))
			})
			It("add valid rdata before invalid rdata", func() {
				Expect(set.Len()).To(Equal(1))
			})
		})
		When("valid rdata", func() {
			BeforeEach(func() {
				err = dnsutils.SetRdata(set, []string{"192.168.0.1", "172.16.0.1"})
			})
			It("successful", func() {
				Expect(err).To(Succeed())
			})
			It("set rr", func() {
				Expect(dnsutils.GetRDATASlice(set)).To(Equal([]string{"192.168.0.1", "172.16.0.1"}))
			})
		})
	})

	Context("ConvertStringToType", func() {
		var (
			res uint16
			err error
		)
		When("type is defined", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToType("A")
			})
			It("returns code", func() {
				Expect(res).To(Equal(dns.TypeA))
			})
			It("no error", func() {
				Expect(err).To(Succeed())
			})
		})
		When("type is not define, and it's not match TYPE*", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToType("HOGE")
			})
			It("returns ErrInvalid", func() {
				Expect(err).To(Equal(dnsutils.ErrInvalid))
			})
		})
		When("type is not define, and it's match TYPE*, but matche string is not integer", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToType("TYPE0001G")
			})
			It("returns ErrInvalid", func() {
				Expect(err).To(Equal(dnsutils.ErrInvalid))
			})
		})
		When("type is not define, and it's match TYPE*, but matche string is not uint", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToType("TYPE-1")
			})
			It("returns ErrInvalid", func() {
				Expect(err).To(Equal(dnsutils.ErrInvalid))
			})
		})
		When("type is not define, and it's match TYPE*, but matche string is not uint16", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToType("TYPE65536")
			})
			It("returns ErrInvalid", func() {
				Expect(err).To(Equal(dnsutils.ErrInvalid))
			})
		})
		When("type is not define, and it's match TYPE*, matche string is uint16", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToType("TYPE65535")
			})
			It("returns code", func() {
				Expect(res).To(Equal(uint16(math.MaxUint16)))
			})
			It("no error", func() {
				Expect(err).To(Succeed())
			})
		})
	})
	Context("ConvertClassToString", func() {
		var (
			res dns.Class
			err error
		)
		When("class is defined", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToClass("IN")
			})
			It("returns class", func() {
				Expect(res).To(Equal(dns.Class(dns.ClassINET)))
			})
			It("no error", func() {
				Expect(err).To(Succeed())
			})
		})
		When("class is not define, and it's not match CLASS*", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToClass("HOGE")
			})
			It("returns ErrInvalid", func() {
				Expect(err).To(Equal(dnsutils.ErrInvalid))
			})
		})
		When("class is not define, and it's match CLASS*, but matche string is not integer", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToClass("CLASS0001G")
			})
			It("returns ErrInvalid", func() {
				Expect(err).To(Equal(dnsutils.ErrInvalid))
			})
		})
		When("class is not define, and it's match CLASS*, but matche string is not uint", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToClass("CLASS-1")
			})
			It("returns ErrInvalid", func() {
				Expect(err).To(Equal(dnsutils.ErrInvalid))
			})
		})
		When("type is not define, and it's match CLASS*, but matche string is not uint16", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToClass("CLASS65536")
			})
			It("returns ErrInvalid", func() {
				Expect(err).To(Equal(dnsutils.ErrInvalid))
			})
		})
		When("type is not define, and it's match CLASS*, matche string is uint16", func() {
			BeforeEach(func() {
				res, err = dnsutils.ConvertStringToClass("CLASS65535")
			})
			It("returns code", func() {
				Expect(res).To(Equal(dns.Class(math.MaxUint16)))
			})
			It("no error", func() {
				Expect(err).To(Succeed())
			})
		})
	})

	Context("ConvertTypeToString", func() {
		var (
			res string
		)
		When("type is defined", func() {
			BeforeEach(func() {
				res = dnsutils.ConvertTypeToString(dns.TypeA)
			})
			It("returns code", func() {
				Expect(res).To(Equal("A"))
			})
		})
		When("type is not define", func() {
			BeforeEach(func() {
				res = dnsutils.ConvertTypeToString(65534)
			})
			It("returns ErrInvalid", func() {
				Expect(res).To(Equal("TYPE65534"))
			})
		})
	})
	Context("ConvertClassToString", func() {
		var (
			res string
		)
		When("class is defined", func() {
			BeforeEach(func() {
				res = dnsutils.ConvertClassToString(dns.ClassINET)
			})
			It("returns code", func() {
				Expect(res).To(Equal("IN"))
			})
		})
		When("class is not define", func() {
			BeforeEach(func() {
				res = dnsutils.ConvertClassToString(65534)
			})
			It("returns ErrInvalid", func() {
				Expect(res).To(Equal("CLASS65534"))
			})
		})
	})
	Context("Test RemoveNameNode", func() {
		var (
			ok                                              bool
			aRRSet, aaaaRRSet, blueRRSet                    *dnsutils.RRSet
			root, www1, www2, www3, www4, blue, alpha, beta *dnsutils.NameNode
			a11                                             = MustNewRR("example.jp. IN A 192.168.0.1")
			a12                                             = MustNewRR("example.jp. IN A 192.168.0.2")
			aaaa11                                          = MustNewRR("example.jp. IN AAAA 2001:db8::1")
			aaaa12                                          = MustNewRR("example.jp. IN AAAA 2001:db8::2")
			blueA                                           = MustNewRR("blue.www4.example.jp. IN AAAA 2001:db8::1")
		)
		BeforeEach(func() {
			root = MustNewNameNode("example.jp", dns.ClassINET)
			www1 = MustNewNameNode("www1.example.jp", dns.ClassINET)
			www2 = MustNewNameNode("www2.example.jp", dns.ClassINET)
			www3 = MustNewNameNode("www3.example.jp", dns.ClassINET)
			www4 = MustNewNameNode("www4.example.jp", dns.ClassINET)
			root.AddChildNameNode(www1)
			root.AddChildNameNode(www2)
			root.AddChildNameNode(www3)
			root.AddChildNameNode(www4)
			blue = MustNewNameNode("blue.www4.example.jp", dns.ClassINET)
			www4.AddChildNameNode(blue)
			alpha = MustNewNameNode("alpha.blue.www4.example.jp", dns.ClassINET)
			blue.AddChildNameNode(alpha)
			beta = MustNewNameNode("beta.alpha.blue.www4.example.jp", dns.ClassINET)
			alpha.AddChildNameNode(beta)
			aRRSet = MustNewRRSet("example.jp", 0, dns.ClassINET, dns.TypeA, []dns.RR{a11, a12})
			aaaaRRSet = MustNewRRSet("example.jp", 0, dns.ClassINET, dns.TypeAAAA, []dns.RR{aaaa11, aaaa12})
			root.SetRRSet(aRRSet)
			root.SetRRSet(aaaaRRSet)
			blueRRSet = MustNewRRSet("blue.www4.example.jp", 0, dns.ClassINET, dns.TypeA, []dns.RR{blueA})
			blue.SetRRSet(blueRRSet)
		})
		It("can remove directly child node", func() {
			err := dnsutils.RemoveNameNode(root, "www1.example.jp")
			Expect(err).To(Succeed())
			_, ok := root.GetNameNode("www1.example.jp")
			Expect(ok).To(BeFalse())
		})
		It("no error, if name not exist", func() {
			_, ok := root.GetNameNode("www-not-exist.example.jp")
			Expect(ok).To(BeFalse())
			err := dnsutils.RemoveNameNode(root, "www-not-exist.example.jp")
			Expect(err).To(Succeed())
		})
		It("can remove grand child and remove ENT node", func() {
			_, ok = root.GetNameNode("www4.example.jp")
			Expect(ok).To(BeTrue())
			err := dnsutils.RemoveNameNode(root, "blue.www4.example.jp")
			Expect(err).To(Succeed())
			_, ok = root.GetNameNode("www4.example.jp")
			Expect(ok).To(BeFalse())
			_, ok = root.GetNameNode("blue.www4.example.jp")
			Expect(ok).To(BeFalse())
			_, ok = root.GetNameNode("alpha.blue.www4.example.jp")
			Expect(ok).To(BeFalse())
		})
		It("can remove grand child and not remove no ENT node", func() {
			err := dnsutils.RemoveNameNode(root, "beta.alpha.blue.www4.example.jp")
			Expect(err).To(Succeed())
			_, ok := root.GetNameNode("www4.example.jp")
			Expect(ok).To(BeTrue())
			_, ok = root.GetNameNode("blue.www4.example.jp")
			Expect(ok).To(BeTrue())
			_, ok = root.GetNameNode("alpha.blue.www4.example.jp")
			Expect(ok).To(BeFalse())
			_, ok = root.GetNameNode("beta.alpha.blue.www4.example.jp")
			Expect(ok).To(BeFalse())
		})
		It("can not be remove not sub domain", func() {
			err := dnsutils.RemoveNameNode(root, "example.jp")
			Expect(err).To(HaveOccurred())
			err = dnsutils.RemoveNameNode(root, "example2.jp")
			Expect(err).To(HaveOccurred())
			err = dnsutils.RemoveNameNode(root, "jp")
			Expect(err).To(HaveOccurred())
		})
		When("name node broken", func() {
			var (
				err error
				bn  *BrokenNode
			)
			BeforeEach(func() {
				bn = &BrokenNode{
					NameNode: MustNewNameNode("example.jp", dns.ClassINET),
					Children: map[string]dnsutils.NameNodeInterface{
						"www.west.example.jp.": MustNewNameNode("www.west.example.jp", dns.ClassINET),
					},
				}
				err = dnsutils.RemoveNameNode(bn, "www.west.example.jp")
			})
			It("returns ErrNameTreeBroken", func() {
				Expect(err).To(Equal(dnsutils.ErrNameTreeBroken))
			})
		})
		When("root name node is root", func() {
			var (
				err  error
				root *dnsutils.NameNode
			)
			BeforeEach(func() {
				root, err = dnsutils.NewNameNode(".", dns.ClassINET)
				Expect(err).To(Succeed())
				err = dnsutils.RemoveNameNode(root, ".")
			})
			It("returns ErrNameTreeBroken", func() {
				Expect(err).To(Equal(dnsutils.ErrRemoveItself))
			})
		})
	})
	Context("Test SetNameNode", func() {
		var (
			g    *TestGenerator
			root *dnsutils.NameNode
		)
		BeforeEach(func() {
			g = &TestGenerator{
				Generator: &dnsutils.DefaultGenerator{},
			}
			root = MustNewNameNode("example.jp", dns.ClassINET)
		})
		It("can not set name that is not subdomain", func() {
			example2 := MustNewNameNode("example2.jp", dns.ClassINET)
			err := dnsutils.SetNameNode(root, example2, nil)
			Expect(err).To(HaveOccurred())
		})
		It("can set directly child node", func() {
			www5 := MustNewNameNode("www5.example.jp", dns.ClassINET)
			err := dnsutils.SetNameNode(root, www5, nil)
			Expect(err).To(Succeed())
			nameNode, ok := root.GetNameNode("www5.example.jp")
			Expect(ok).To(BeTrue())
			Expect(nameNode).To(Equal(www5))
		})
		It("can set not directly child node", func() {
			red := MustNewNameNode("red.www5.example.jp", dns.ClassINET)
			err := dnsutils.SetNameNode(root, red, nil)
			Expect(err).To(Succeed())
			nameNode, ok := root.GetNameNode("red.www5.example.jp")
			Expect(ok).To(BeTrue())
			Expect(nameNode).To(Equal(red))
		})
		It("can replace exist node", func() {
			newwww1 := MustNewNameNode("www1.example.jp", dns.ClassINET)
			set := MustNewRRSet("www.example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{
				MustNewRR("www1.example.jp. 300 IN A 192.168.10.0"),
			})
			newwww1.SetRRSet(set)
			err := dnsutils.SetNameNode(root, newwww1, nil)
			Expect(err).To(Succeed())
			nameNode, ok := root.GetNameNode("www1.example.jp")
			Expect(ok).To(BeTrue())
			Expect(nameNode).To(Equal(newwww1))
		})
		When("failed to create name node", func() {
			var (
				err error
			)
			BeforeEach(func() {
				g.NewNewNameNodeErr = fmt.Errorf("failed to run NewNameNode")
				www5 := MustNewNameNode("www5.example.jp", dns.ClassINET)
				err = dnsutils.SetNameNode(root, www5, g)
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
	})
	Context("Test GetAllParentNames", func() {
		var (
			names []string
			ok    bool
		)
		When("valid names", func() {
			When("level is 0", func() {
				BeforeEach(func() {
					names, ok = dnsutils.GetAllParentNames("3.example.jp", 0)
				})
				It("returns true", func() {
					Expect(ok).To(BeTrue())
					Expect(names).To(Equal([]string{
						"jp.",
						"example.jp.",
						"3.example.jp.",
					}))
				})
			})
			When("level is 1", func() {
				BeforeEach(func() {
					names, ok = dnsutils.GetAllParentNames("3.example.jp", 1)
				})
				It("returns true", func() {
					Expect(ok).To(BeTrue())
					Expect(names).To(Equal([]string{
						"example.jp.",
						"3.example.jp.",
					}))
				})
			})
			When("level is 2", func() {
				BeforeEach(func() {
					names, ok = dnsutils.GetAllParentNames("3.example.jp", 2)
				})
				It("returns true", func() {
					Expect(ok).To(BeTrue())
					Expect(names).To(Equal([]string{
						"3.example.jp.",
					}))
				})
			})
			When("level is 3", func() {
				BeforeEach(func() {
					names, ok = dnsutils.GetAllParentNames("3.example.jp", 3)
				})
				It("returns true", func() {
					Expect(ok).To(BeTrue())
					Expect(names).To(Equal([]string{}))
				})
			})
		})
		When("invalid domain name", func() {
			BeforeEach(func() {
				names, ok = dnsutils.GetAllParentNames(".example.jp", 0)
			})
			It("returns false", func() {
				Expect(ok).To(BeFalse())
			})
		})
	})
	Context("Test SortNamesFunc", func() {
		var (
			names []string
			err   error
		)
		When("invalid names", func() {
			BeforeEach(func() {
				names = []string{
					"example.jp.",
					".example.jp",
				}
				err = dnsutils.SortNames(names)
			})
			It("return err", func() {
				Expect(err).To(Equal(dnsutils.ErrBadName))
				Expect(names).To(Equal([]string{
					"example.jp.",
					".example.jp",
				}))
			})
		})
		When("valid names", func() {
			BeforeEach(func() {
				names = []string{
					"a.example",
					"zABC.a.EXAMPLE",
					"yljkjljk.a.example",
					"Z.a.example",
					"*.z.example",
					"\200.z.example",
					"z.example",
					"\001.z.example",
				}
				err = dnsutils.SortNames(names)
			})
			It("return err", func() {
				Expect(err).To(Succeed())
				Expect(names).To(Equal([]string{
					"a.example",
					"yljkjljk.a.example",
					"Z.a.example",
					"zABC.a.EXAMPLE",
					"z.example",
					"\001.z.example",
					"*.z.example",
					"\200.z.example",
				}))
			})
		})
		When("valid names2", func() {
			BeforeEach(func() {
				names = []string{
					"example.jp.",
					"*.example.jp.",
					"\000.example.jp.",
				}
				err = dnsutils.SortNames(names)
			})
			It("return err", func() {
				Expect(err).To(Succeed())
				Expect(names).To(Equal([]string{
					"example.jp.",
					"\000.example.jp.",
					"*.example.jp.",
				}))
			})
		})
	})
})
