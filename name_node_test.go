package dnsutils_test

import (
	"fmt"
	"sort"
	"testing"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
	. "github.com/mimuret/dnsutils/testtool"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestDNSUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "dnsutils Suite")
}

var _ = Describe("NameNode", func() {
	var (
		aRRSet, aaaaRRSet, blueRRSet                    *dnsutils.RRSet
		root, www1, www2, www3, www4, blue, alpha, beta *dnsutils.NameNode
		a11                                             = MustNewRR("example.jp. IN A 192.168.0.1")
		a12                                             = MustNewRR("example.jp. IN A 192.168.0.2")
		aaaa11                                          = MustNewRR("example.jp. IN AAAA 2001:db8::1")
		aaaa12                                          = MustNewRR("example.jp. IN AAAA 2001:db8::2")
		blueA                                           = MustNewRR("blue.www4.example.jp. IN AAAA 2001:db8::1")
		txt1                                            = MustNewRR(`example.jp. 300 IN TXT "hogehoge"`)
		txt2                                            = MustNewRR(`example.jp. 300 IN TXT "hugahuga"`)
		cname                                           = MustNewRR(`example.jp. 300 IN CNAME www.example.jp.`)
		dname                                           = MustNewRR(`example.jp. 300 IN DNAME example.net.`)
	)
	BeforeEach(func() {
		root = dnsutils.NewNameNode("example.jp", dns.ClassINET)
		www1 = dnsutils.NewNameNode("www1.example.jp", dns.ClassINET)
		www2 = dnsutils.NewNameNode("www2.example.jp", dns.ClassINET)
		www3 = dnsutils.NewNameNode("www3.example.jp", dns.ClassINET)
		www4 = dnsutils.NewNameNode("www4.example.jp", dns.ClassINET)
		root.AddChildNode(www1)
		root.AddChildNode(www2)
		root.AddChildNode(www3)
		root.AddChildNode(www4)
		blue = dnsutils.NewNameNode("blue.www4.example.jp", dns.ClassINET)
		www4.AddChildNode(blue)
		alpha = dnsutils.NewNameNode("alpha.blue.www4.example.jp", dns.ClassINET)
		blue.AddChildNode(alpha)
		beta = dnsutils.NewNameNode("beta.alpha.blue.www4.example.jp", dns.ClassINET)
		alpha.AddChildNode(beta)
		aRRSet = dnsutils.NewRRSet("example.jp", 0, dns.ClassINET, dns.TypeA, []dns.RR{a11, a12})
		aaaaRRSet = dnsutils.NewRRSet("example.jp", 0, dns.ClassINET, dns.TypeAAAA, []dns.RR{aaaa11, aaaa12})
		root.SetRRSet(aRRSet)
		root.SetRRSet(aaaaRRSet)
		blueRRSet = dnsutils.NewRRSet("blue.www4.example.jp", 0, dns.ClassINET, dns.TypeA, []dns.RR{blueA})
		blue.SetRRSet(blueRRSet)

	})
	Context("Test for NameNode", func() {
		It("GetName returned canonical Name", func() {
			nn := dnsutils.NewNameNode("example.jp", dns.ClassINET)
			Expect(nn).NotTo(BeNil())
			Expect(nn.GetName()).To(Equal("example.jp."))
		})
	})
	Context("Test for GetNameNode", func() {
		It("returns current node with true (strict match)", func() {
			nameNode, ok := root.GetNameNode("example.jp")
			Expect(ok).To(BeTrue())
			Expect(nameNode).To(Equal(root))
		})
		It("returns child node with true (strict match)", func() {
			nameNode, ok := root.GetNameNode("www1.example.jp")
			Expect(ok).To(BeTrue())
			Expect(nameNode).To(Equal(www1))
		})
		It("returns grand child node with true (strict match)", func() {
			nameNode, ok := root.GetNameNode("blue.www4.example.jp")
			Expect(ok).To(BeTrue())
			Expect(nameNode).To(Equal(blue))
		})
		It("returns nearly node with false (loose match)", func() {
			nameNode, ok := root.GetNameNode("apple.www1.example.jp")
			Expect(ok).To(BeFalse())
			Expect(nameNode).To(Equal(www1))
		})
		It("returns grand child node with false (loose match)", func() {
			nameNode, ok := root.GetNameNode("apple.blue.www4.example.jp")
			Expect(ok).To(BeFalse())
			Expect(nameNode).To(Equal(blue))
		})
		It("returns nil with false (if name is not node subdomain name and equals to node domain name)", func() {
			nameNode, ok := root.GetNameNode("example2.jp")
			Expect(ok).To(BeFalse())
			Expect(nameNode).To(BeNil())
			nameNode, ok = root.GetNameNode("jp")
			Expect(ok).To(BeFalse())
			Expect(nameNode).To(BeNil())
		})
	})
	Context("Test for CopyChildNodes", func() {
		It("returns child node", func() {
			Expect(root.CopyChildNodes()).To(Equal(map[string]dnsutils.NameNodeInterface{
				"www1.example.jp.": www1,
				"www2.example.jp.": www2,
				"www3.example.jp.": www3,
				"www4.example.jp.": www4,
			}))
		})
	})
	Context("Test for CopyRRSetMap", func() {
		It("returns RRSetInterface", func() {
			Expect(root.CopyRRSetMap()).To(Equal(map[uint16]dnsutils.RRSetInterface{
				dns.TypeA:    aRRSet,
				dns.TypeAAAA: aaaaRRSet,
			}))
		})
	})
	Context("Test for GetRRSet", func() {
		It("returns RRSetInterface if exist", func() {
			Expect(root.GetRRSet(dns.TypeA)).To(Equal(aRRSet))
		})
		It("returns nil if not exist", func() {
			Expect(root.GetRRSet(dns.TypeCNAME)).To(BeNil())
		})
	})
	Context("Test for SetValue", func() {
		When("name not equals", func() {
			It("returns ErrNameNotEqual", func() {
				a := dnsutils.NewNameNode("example.net.", dns.ClassINET)
				b := dnsutils.NewNameNode("www.example.net.", dns.ClassINET)
				Expect(a.SetValue(b)).To(Equal(dnsutils.ErrNameNotEqual))
			})
		})
		When("name not class", func() {
			It("returns ErrNameNotEqual", func() {
				a := dnsutils.NewNameNode("example.net.", dns.ClassINET)
				b := dnsutils.NewNameNode("example.net.", dns.ClassCHAOS)
				Expect(a.SetValue(b)).To(Equal(dnsutils.ErrClassNotEqual))
			})
		})
		When("name not class", func() {
			It("returns nil", func() {
				a := dnsutils.NewNameNode("example.net.", dns.ClassINET)
				b := dnsutils.NewNameNode("example.net.", dns.ClassINET)
				brr := MustNewRR("example.net. 300 IN A 192.169.0.0")
				b.SetRRSet(dnsutils.NewRRSetFromRR(brr))
				Expect(a.SetValue(b)).To(BeNil())
				Expect(a.GetRRSet(dns.TypeA).GetRRs()).To(Equal([]dns.RR{brr}))
			})
		})
	})
	Context("Test for IterateNameRRSet", func() {
		It("can iterate all rrset", func() {
			rrsetMap := map[uint16]dnsutils.RRSetInterface{}
			root.IterateNameRRSet(func(set dnsutils.RRSetInterface) error {
				rrsetMap[set.GetRRtype()] = set
				return nil
			})
			Expect(rrsetMap).To(Equal(map[uint16]dnsutils.RRSetInterface{
				dns.TypeA:    aRRSet,
				dns.TypeAAAA: aaaaRRSet,
			}))
		})
		It("can return err", func() {
			err := root.IterateNameRRSet(func(set dnsutils.RRSetInterface) error {
				return fmt.Errorf("error")
			})
			Expect(err).NotTo(BeNil())
		})
	})
	Context("Test for IterateNameNode", func() {
		It("can iterate all node", func() {
			names := sort.StringSlice{}
			target := sort.StringSlice{"example.jp.", "www1.example.jp.", "www2.example.jp.", "www3.example.jp.", "www4.example.jp.", "blue.www4.example.jp.", "alpha.blue.www4.example.jp.", "beta.alpha.blue.www4.example.jp."}
			root.IterateNameNode(func(n dnsutils.NameNodeInterface) error {
				names = append(names, n.GetName())
				return nil
			})
			names.Sort()
			target.Sort()
			Expect(names).To(Equal(target))
		})
		It("can return err", func() {
			err := root.IterateNameNode(func(n dnsutils.NameNodeInterface) error {
				return fmt.Errorf("error")
			})
			Expect(err).NotTo(BeNil())
			err = root.IterateNameNode(func(n dnsutils.NameNodeInterface) error {
				if n.GetName() != "example.jp." {
					return fmt.Errorf("error")
				}
				return nil
			})
			Expect(err).NotTo(BeNil())
		})

	})
	Context("Test AddChildNode", func() {
		It("can set directly child node", func() {
			www5 := dnsutils.NewNameNode("www5.example.jp", dns.ClassINET)
			err := root.AddChildNode(www5)
			Expect(err).To(BeNil())
			nameNode, ok := root.GetNameNode("www5.example.jp")
			Expect(ok).To(BeTrue())
			Expect(nameNode).To(Equal(www5))
		})
		It("can't set not directly child node", func() {
			red := dnsutils.NewNameNode("red.www5.example.jp", dns.ClassINET)
			err := root.AddChildNode(red)
			Expect(err).NotTo(BeNil())
		})
		It("can't set child node if already exist", func() {
			err := root.AddChildNode(www4)
			Expect(err).NotTo(BeNil())
		})
	})
	Context("Test SetNameNode", func() {
		It("can not set name that is not subdomain", func() {
			example2 := dnsutils.NewNameNode("example2.jp", dns.ClassINET)
			err := root.SetNameNode(example2)
			Expect(err).NotTo(BeNil())
		})
		It("can set directly child node", func() {
			www5 := dnsutils.NewNameNode("www5.example.jp", dns.ClassINET)
			err := root.SetNameNode(www5)
			Expect(err).To(BeNil())
			nameNode, ok := root.GetNameNode("www5.example.jp")
			Expect(ok).To(BeTrue())
			Expect(nameNode).To(Equal(www5))
		})
		It("can set not directly child node", func() {
			red := dnsutils.NewNameNode("red.www5.example.jp", dns.ClassINET)
			err := root.SetNameNode(red)
			Expect(err).To(BeNil())
			nameNode, ok := root.GetNameNode("red.www5.example.jp")
			Expect(ok).To(BeTrue())
			Expect(nameNode).To(Equal(red))
		})
		It("can replace exist node", func() {
			newwww1 := dnsutils.NewNameNode("www1.example.jp", dns.ClassINET)
			set := dnsutils.NewRRSet("www.example.jp.", 300, dns.ClassINET, dns.TypeA, []dns.RR{
				MustNewRR("www1.example.jp. 300 IN A 192.168.10.0"),
			})
			newwww1.SetRRSet(set)
			err := root.SetNameNode(newwww1)
			Expect(err).To(BeNil())
			nameNode, ok := root.GetNameNode("www1.example.jp")
			Expect(ok).To(BeTrue())
			Expect(nameNode).To(Equal(newwww1))
		})
	})
	Context("Test RemoveNameNode", func() {
		It("can remove directly child node", func() {
			ok, err := root.RemoveNameNode("www1.example.jp")
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
			_, ok = root.GetNameNode("www1.example.jp")
			Expect(ok).To(BeFalse())
		})
		It("can remove grand child and remove ENT node", func() {
			ok, err := root.RemoveNameNode("blue.www4.example.jp")
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
			_, ok = root.GetNameNode("www4.example.jp")
			Expect(ok).To(BeFalse())
			_, ok = root.GetNameNode("blue.www4.example.jp")
			Expect(ok).To(BeFalse())
			_, ok = root.GetNameNode("alpha.blue.www4.example.jp")
			Expect(ok).To(BeFalse())
		})
		It("can remove grand child and not remove no ENT node", func() {
			ok, err := root.RemoveNameNode("beta.alpha.blue.www4.example.jp")
			Expect(err).To(BeNil())
			Expect(ok).To(BeFalse())
			_, ok = root.GetNameNode("www4.example.jp")
			Expect(ok).To(BeTrue())
			_, ok = root.GetNameNode("blue.www4.example.jp")
			Expect(ok).To(BeTrue())
			_, ok = root.GetNameNode("alpha.blue.www4.example.jp")
			Expect(ok).To(BeFalse())
			_, ok = root.GetNameNode("beta.alpha.blue.www4.example.jp")
			Expect(ok).To(BeFalse())
		})
		It("can not be remove not sub domain", func() {
			_, err := root.RemoveNameNode("example.jp")
			Expect(err).NotTo(BeNil())
			_, err = root.RemoveNameNode("example2.jp")
			Expect(err).NotTo(BeNil())
			_, err = root.RemoveNameNode("jp")
			Expect(err).NotTo(BeNil())
		})
	})
	Context("Test for SetRRSet", func() {
		It("can set rrset", func() {
			set := dnsutils.NewRRSetFromRR(txt1)
			err := root.SetRRSet(set)
			Expect(err).To(BeNil())
			Expect(root.GetRRSet(dns.TypeTXT)).To(Equal(set))
			set = dnsutils.NewRRSetFromRR(txt2)
			dnsutils.NewRRSetFromRR(txt2)
			err = root.SetRRSet(set)
			Expect(err).To(BeNil())
			Expect(root.GetRRSet(dns.TypeTXT)).To(Equal(set))
		})
		It("not able to set rrset, if rrset name is ignore ", func() {
			set := dnsutils.NewRRSet("example2.jp.", 300, dns.ClassINET, dns.TypeTXT, nil)
			err := root.SetRRSet(set)
			Expect(err).NotTo(BeNil())
			set = dnsutils.NewRRSet("jp.", 300, dns.ClassINET, dns.TypeTXT, nil)
			err = root.SetRRSet(set)
			Expect(err).NotTo(BeNil())
			set = dnsutils.NewRRSet("www.example.jp.", 300, dns.ClassINET, dns.TypeTXT, nil)
			err = root.SetRRSet(set)
			Expect(err).NotTo(BeNil())
		})
		It("not able to set both cname and other ", func() {
			set := dnsutils.NewRRSetFromRR(cname)
			err := root.SetRRSet(set)
			Expect(err).NotTo(BeNil())
		})
		It("not able to set both dname and other ", func() {
			set := dnsutils.NewRRSetFromRR(dname)
			err := root.SetRRSet(set)
			Expect(err).NotTo(BeNil())
		})
	})
	Context("Test for RemoveRRSet", func() {
		It("can removeset rrset", func() {
			r1 := MustNewRR("www1.example.net. 30 IN A 192.168.0.1")
			set := dnsutils.NewRRSetFromRRs([]dns.RR{r1})
			node := dnsutils.NewNameNode("www1.example.net.", dns.ClassINET)
			err := node.SetRRSet(set)
			Expect(err).To(BeNil())
			Expect(node.GetRRSet(dns.TypeA)).To(Equal(set))
			node.RemoveRRSet(dns.TypeAAAA)
			Expect(node.GetRRSet(dns.TypeA)).To(Equal(set))
			node.RemoveRRSet(dns.TypeA)
			Expect(node.GetRRSet(dns.TypeA)).To(BeNil())
		})
	})
	Context("Test for RRSetLen", func() {
		It("returns the number of not empty rrset", func() {
			Expect(root.RRSetLen()).To(Equal(2))
			set := dnsutils.NewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeTXT, nil)
			err := root.SetRRSet(set)
			Expect(err).To(BeNil())
			Expect(root.RRSetLen()).To(Equal(2))
			err = set.AddRR(txt1)
			Expect(err).To(BeNil())
			Expect(root.RRSetLen()).To(Equal(3))
		})
	})
})
