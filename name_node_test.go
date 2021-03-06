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
	Context("NewNameNode", func() {
		When("name is domina name", func() {
			It("returned NameNode", func() {
				nn, err := dnsutils.NewNameNode("example.jp", dns.ClassINET)
				Expect(err).To(Succeed())
				Expect(nn).NotTo(BeNil())
				Expect(nn.GetName()).To(Equal("example.jp."))
			})
		})
		When("name is not domina name", func() {
			It("returned NameNode", func() {
				_, err := dnsutils.NewNameNode("..", dns.ClassINET)
				Expect(err).To(HaveOccurred())
			})
		})
	})
	Context("Test for NameNode", func() {
		It("GetName returned canonical Name", func() {
			nn := MustNewNameNode("example.jp", dns.ClassINET)
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
				a := MustNewNameNode("example.net.", dns.ClassINET)
				b := MustNewNameNode("www.example.net.", dns.ClassINET)
				Expect(a.SetValue(b)).To(Equal(dnsutils.ErrNameNotEqual))
			})
		})
		When("name not class", func() {
			It("returns ErrNameNotEqual", func() {
				a := MustNewNameNode("example.net.", dns.ClassINET)
				b := MustNewNameNode("example.net.", dns.ClassCHAOS)
				Expect(a.SetValue(b)).To(Equal(dnsutils.ErrClassNotEqual))
			})
		})
		When("name not class", func() {
			It("returns nil", func() {
				a := MustNewNameNode("example.net.", dns.ClassINET)
				b := MustNewNameNode("example.net.", dns.ClassINET)
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
			Expect(err).To(HaveOccurred())
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
			Expect(err).To(HaveOccurred())
			err = root.IterateNameNode(func(n dnsutils.NameNodeInterface) error {
				if n.GetName() != "example.jp." {
					return fmt.Errorf("error")
				}
				return nil
			})
			Expect(err).To(HaveOccurred())
		})

	})
	Context("Test AddChildNode", func() {
		It("can set directly child node", func() {
			www5 := MustNewNameNode("www5.example.jp", dns.ClassINET)
			err := root.AddChildNameNode(www5)
			Expect(err).To(Succeed())
			nameNode, ok := root.GetNameNode("www5.example.jp")
			Expect(ok).To(BeTrue())
			Expect(nameNode).To(Equal(www5))
		})
		It("can't set not directly child node", func() {
			red := MustNewNameNode("red.www5.example.jp", dns.ClassINET)
			err := root.AddChildNameNode(red)
			Expect(err).To(HaveOccurred())
		})
		It("can't set child node if already exist", func() {
			err := root.AddChildNameNode(www4)
			Expect(err).To(HaveOccurred())
		})
	})
	Context("Test RemoveChildNameNode", func() {
		It("can remove directly child node", func() {
			err := root.RemoveChildNameNode("www1.example.jp")
			Expect(err).To(Succeed())
			_, ok := root.GetNameNode("www1.example.jp")
			Expect(ok).To(BeFalse())
		})
		It("can not be remove not subomain", func() {
			err := root.RemoveChildNameNode("example.jp")
			Expect(err).To(HaveOccurred())
			err = root.RemoveChildNameNode("example2.jp")
			Expect(err).To(HaveOccurred())
			err = root.RemoveChildNameNode("jp")
			Expect(err).To(HaveOccurred())
		})
	})
	Context("Test for SetRRSet", func() {
		It("can set rrset", func() {
			set := dnsutils.NewRRSetFromRR(txt1)
			err := root.SetRRSet(set)
			Expect(err).To(Succeed())
			Expect(root.GetRRSet(dns.TypeTXT)).To(Equal(set))
			set = dnsutils.NewRRSetFromRR(txt2)
			dnsutils.NewRRSetFromRR(txt2)
			err = root.SetRRSet(set)
			Expect(err).To(Succeed())
			Expect(root.GetRRSet(dns.TypeTXT)).To(Equal(set))
		})
		It("not able to set rrset, if rrset name is ignore ", func() {
			set := MustNewRRSet("example2.jp.", 300, dns.ClassINET, dns.TypeTXT, nil)
			err := root.SetRRSet(set)
			Expect(err).To(HaveOccurred())
			set = MustNewRRSet("jp.", 300, dns.ClassINET, dns.TypeTXT, nil)
			err = root.SetRRSet(set)
			Expect(err).To(HaveOccurred())
			set = MustNewRRSet("www.example.jp.", 300, dns.ClassINET, dns.TypeTXT, nil)
			err = root.SetRRSet(set)
			Expect(err).To(HaveOccurred())
		})
		It("not able to set both cname and other ", func() {
			set := dnsutils.NewRRSetFromRR(cname)
			err := root.SetRRSet(set)
			Expect(err).To(HaveOccurred())
		})
		It("not able to set both dname and other ", func() {
			set := dnsutils.NewRRSetFromRR(dname)
			err := root.SetRRSet(set)
			Expect(err).To(HaveOccurred())
		})
	})
	Context("Test for RemoveRRSet", func() {
		It("can removeset rrset", func() {
			r1 := MustNewRR("www1.example.net. 30 IN A 192.168.0.1")
			set := dnsutils.NewRRSetFromRRs([]dns.RR{r1})
			node := MustNewNameNode("www1.example.net.", dns.ClassINET)
			err := node.SetRRSet(set)
			Expect(err).To(Succeed())
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
			set := MustNewRRSet("example.jp.", 300, dns.ClassINET, dns.TypeTXT, nil)
			err := root.SetRRSet(set)
			Expect(err).To(Succeed())
			Expect(root.RRSetLen()).To(Equal(2))
			err = set.AddRR(txt1)
			Expect(err).To(Succeed())
			Expect(root.RRSetLen()).To(Equal(3))
		})
	})
})
