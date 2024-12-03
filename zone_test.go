package dnsutils_test

import (
	"bytes"
	_ "embed"
	"encoding/json"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
	. "github.com/mimuret/dnsutils/testtool"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/example.jp.normal
var testZoneNormal []byte

//go:embed testdata/example.jp.error
var testZoneError []byte

//go:embed testdata/example.jp.out-of-zone
var testZoneOutofZoneError []byte

//go:embed testdata/example.jp.normalize
var testZoneNormalize []byte

//go:embed testdata/example.jp.name-error
var testZoneNameError []byte

//go:embed testdata/example.jp.parse
var testZoneParseError []byte

//go:embed testdata/example.jp.normal.json
var testZoneJsonNormal []byte

//go:embed testdata/example.jp.name-error.json
var testZoneJsonNameError []byte

var _ = Describe("Zone", func() {
	var (
		err error
		z   *dnsutils.Zone
	)
	BeforeEach(func() {
		z, err = dnsutils.NewZone("example.jp", dns.ClassINET, nil)
		Expect(err).To(Succeed())
	})
	Context("Test for NewZone", func() {
		When("valid zone name", func() {
			It("returns zone", func() {
				Expect(z).NotTo(BeNil())
			})
		})
		When("invalid zone name", func() {
			BeforeEach(func() {
				_, err = dnsutils.NewZone("...", dns.ClassINET, nil)
			})
			It("returns ErrBadName", func() {
				Expect(err).To(Equal(dnsutils.ErrBadName))
			})
		})
	})
	Context("Test for GetName", func() {
		It("returns canonical zone name", func() {
			Expect(z.GetName()).To(Equal("example.jp."))
		})
	})
	Context("Test for GetRootNode", func() {
		It("returns root NameNode", func() {
			Expect(z.GetRootNode().GetName()).To(Equal("example.jp."))
		})
	})
	Context("Test for Read", func() {
		When("valid data", func() {
			BeforeEach(func() {
				testZoneNormalBuf := bytes.NewBuffer(testZoneNormal)
				z = &dnsutils.Zone{}
				err = z.Read(testZoneNormalBuf)
			})
			It("can read data", func() {
				Expect(err).To(Succeed())
				Expect(z.GetName()).To(Equal("example.jp."))
				Expect(z.GetClass()).To(Equal(dns.Class(dns.ClassINET)))
				Expect(z.GetRootNode()).NotTo(BeNil())
				nn, ok := z.GetRootNode().GetNameNode("test.hoge.example.jp")
				Expect(ok).To(BeTrue())
				Expect(nn.GetName()).To(Equal("test.hoge.example.jp."))
				set := nn.GetRRSet(dns.TypeA)
				Expect(set).NotTo(BeNil())
				Expect(set.GetRRtype()).To(Equal(dns.TypeA))
				Expect(set.GetRRs()).To(Equal([]dns.RR{
					MustNewRR("test.hoge.example.jp. 3600 IN A 192.168.2.1"),
					MustNewRR("test.hoge.example.jp. 3600 IN A 192.168.2.2"),
				}))
			})
		})
		When("normalize", func() {
			BeforeEach(func() {
				testZoneNormalBuf := bytes.NewBuffer(testZoneNormalize)
				z = &dnsutils.Zone{}
				err = z.Read(testZoneNormalBuf)
			})
			It("can read data", func() {
				Expect(err).To(Succeed())
				Expect(z.GetName()).To(Equal("example.jp."))
				Expect(z.GetClass()).To(Equal(dns.Class(dns.ClassINET)))
				Expect(z.GetRootNode()).NotTo(BeNil())
				_, ok := z.GetRootNode().GetNameNode("sub1.example.jp.")
				Expect(ok).To(BeTrue())
				_, ok = z.GetRootNode().GetNameNode("ns.sub1.example.jp.")
				Expect(ok).To(BeTrue())
				_, ok = z.GetRootNode().GetNameNode("sub2.example.jp.")
				Expect(ok).To(BeTrue())
				_, ok = z.GetRootNode().GetNameNode("ns.sub2.example.jp.")
				Expect(ok).To(BeFalse())
				_, ok = z.GetRootNode().GetNameNode("sub3.example.jp.")
				Expect(ok).To(BeTrue())
				_, ok = z.GetRootNode().GetNameNode("ns.sub.sub3.example.jp.")
				Expect(ok).To(BeTrue())
			})
		})
		When("out of zone data", func() {
			BeforeEach(func() {
				testZoneNormalBuf := bytes.NewBuffer(testZoneOutofZoneError)
				z = &dnsutils.Zone{}
				err = z.Read(testZoneNormalBuf)
			})
			It("can't read not valid data", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("include can't add RR (duplicate cname)", func() {
			BeforeEach(func() {
				testZoneNormalBuf := bytes.NewBuffer(testZoneError)
				z = &dnsutils.Zone{}
				err = z.Read(testZoneNormalBuf)
			})
			It("can't read not valid data", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("include invalid format", func() {
			BeforeEach(func() {
				testZoneNormalBuf := bytes.NewBuffer(testZoneParseError)
				z = &dnsutils.Zone{}
				err = z.Read(testZoneNormalBuf)
			})
			It("can't parse record", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("include not zone subdomain", func() {
			BeforeEach(func() {
				testZoneNormalBuf := bytes.NewBuffer(testZoneNameError)
				z = &dnsutils.Zone{}
				err = z.Read(testZoneNormalBuf)
			})
			It("can't read", func() {
				Expect(err).To(HaveOccurred())
			})
		})
	})
	Context("Test for UnmarshalJSON", func() {
		BeforeEach(func() {
			z = &dnsutils.Zone{}
		})
		When("valid date", func() {
			BeforeEach(func() {
				err = json.Unmarshal(testZoneJsonNormal, z)
			})
			It("returns not error", func() {
				Expect(err).To(Succeed())
				testZoneNormalBuf := bytes.NewBuffer(testZoneNormal)
				z2, _ := dnsutils.NewZone("example.jp", dns.ClassINET, nil)
				err := z2.Read(testZoneNormalBuf)
				Expect(err).To(Succeed())
				Expect(z2).To(Equal(z2))
			})
		})
		When("json type invalid", func() {
			BeforeEach(func() {
				err = json.Unmarshal([]byte(`{"name":"example.jp.","class":1}`), z)
			})
			It("returns not error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(MatchRegexp("failed to parse json format"))
			})
		})
		When("name invalid", func() {
			BeforeEach(func() {
				err = json.Unmarshal([]byte(`{"name":"example..jp.","class":"IN"}`), z)
			})
			It("returns not error", func() {
				Expect(err).To(Equal(dnsutils.ErrBadName))
			})
		})
		When("class invalid", func() {
			BeforeEach(func() {
				err = json.Unmarshal([]byte(`{"name":"example.jp.","class":"HOGE"}`), z)
			})
			It("returns not error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(MatchRegexp("invalid class"))
			})
		})
		When("rrset invalid", func() {
			BeforeEach(func() {
				err = json.Unmarshal([]byte(testZoneJsonNameError), z)
			})
			It("returns not error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(MatchRegexp("failed to set node"))
			})
		})
	})
	Context("Test for MarshalJSON", func() {
		var (
			z   *dnsutils.Zone
			err error
			bs  []byte
		)
		BeforeEach(func() {
			testZoneNormalBuf := bytes.NewBuffer(testZoneNormal)
			z = &dnsutils.Zone{}
			err = z.Read(testZoneNormalBuf)
			Expect(err).To(Succeed())
			bs, err = json.Marshal(z)
		})
		It("returns json data", func() {
			Expect(err).To(Succeed())
			Expect(bs).To(MatchJSON(testZoneJsonNormal))
		})
	})
})
