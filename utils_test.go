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
				n, _ := dnsutils.NewNameNode("example.jp", dns.ClassINET)
				n.SetRRSet(dnsutils.NewRRSetFromRR(a))
				Expect(dnsutils.IsENT(n)).To(BeFalse())
			})
		})
		When("rrset exist and rdata not exist", func() {
			It("returns true", func() {
				n, _ := dnsutils.NewNameNode("example.jp", dns.ClassINET)
				n.SetRRSet(dnsutils.NewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeA, nil))
				Expect(dnsutils.IsENT(n)).To(BeTrue())
			})
		})
		When("rrset not exist", func() {
			It("returns true", func() {
				n, _ := dnsutils.NewNameNode("example.jp", dns.ClassINET)
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
				root, err := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				Expect(err).To(Succeed())
				root.SetRRSet(set)
				Expect(dnsutils.GetRRSetOrCreate(root, dns.TypeA, 300)).To(Equal(set))
			})
		})
		When("not exist rrset", func() {
			It("returns new rrset", func() {
				root, err := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				Expect(err).To(Succeed())
				a4set := dnsutils.GetRRSetOrCreate(root, dns.TypeAAAA, 300)
				Expect(a4set.GetRRtype()).To(Equal(dns.TypeAAAA))
				Expect(a4set.GetName()).To(Equal("example.jp."))
			})
		})
	})
	Context("GetNodeOrCreate", func() {
		When("invalid name ", func() {
			It("returns ErrBadName", func() {
				root, _ := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				_, err := dnsutils.GetNameNodeOrCreate(root, "..www.example.jp")
				Expect(err).To(Equal(dnsutils.ErrBadName))
			})
		})
		When("not name node subdomain or same domain", func() {
			It("returns ErrNotSubdomain", func() {
				root, _ := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				_, err := dnsutils.GetNameNodeOrCreate(root, "example.com")
				Expect(err).To(Equal(dnsutils.ErrNotSubdomain))
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
				root.SetNameNode(wwwNode)
				Expect(dnsutils.GetNameNodeOrCreate(root, "www.example.jp")).To(Equal(wwwNode))
			})
		})
		When("not exist node", func() {
			It("returns new node", func() {
				root, err := dnsutils.NewNameNode("example.jp.", dns.ClassINET)
				Expect(err).To(Succeed())
				wwwNode, err := dnsutils.GetNameNodeOrCreate(root, "www.example.jp")
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
			set := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{
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
			set = dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, nil)
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
				set = dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeCNAME, nil)
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
				Expect(res).To(Equal(uint16(65535)))
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
				Expect(res).To(Equal(dns.Class(65535)))
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
})
