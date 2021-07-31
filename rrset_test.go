package dnsutils_test

import (
	"encoding/json"
	"net"

	. "github.com/mimuret/dnsutils/testtool"
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
	Context("test for NewRRSetFromRR", func() {
		When("rr is nil", func() {
			It("returns nil", func() {
				Expect(dnsutils.NewRRSetFromRR(nil)).To(BeNil())
			})
		})
		When("rr is not nil", func() {
			It("returns rrset", func() {
				set := dnsutils.NewRRSetFromRR(a11)
				Expect(set).NotTo(BeNil())
				Expect(set.GetName()).To(Equal("example.jp."))
				Expect(set.GetTTL()).To(Equal(uint32(300)))
				Expect(set.GetClass()).To(Equal(dns.Class(dns.ClassINET)))
				Expect(set.GetRRtype()).To(Equal(dns.TypeA))
				Expect(set.GetRRs()).To(Equal([]dns.RR{a11}))
			})
		})
	})
	Context("test for NewRRSetFromRRs", func() {
		When("rrs is nil", func() {
			It("returns nil", func() {
				Expect(dnsutils.NewRRSetFromRRs(nil)).To(BeNil())
			})
		})
		When("rrs is empty", func() {
			It("returns nil", func() {
				Expect(dnsutils.NewRRSetFromRRs([]dns.RR{})).To(BeNil())
			})
		})
		It("name,ttl,type, or class ignore, returns nil", func() {
			Expect(dnsutils.NewRRSetFromRRs([]dns.RR{a11, soa1})).To(BeNil())
		})
		It("type is CNAME, multiple RR, returns nil", func() {
			Expect(dnsutils.NewRRSetFromRRs([]dns.RR{cname1, cname2})).To(BeNil())
		})
		It("type is SOA, multiple RR, returns nil", func() {
			Expect(dnsutils.NewRRSetFromRRs([]dns.RR{soa1, soa2})).To(BeNil())
		})
		When("rrs is same name,ttl,type,class. (However type is not CNAME, SOA)", func() {
			It("returns rrset", func() {
				set := dnsutils.NewRRSetFromRRs([]dns.RR{a11, a12})
				Expect(set).NotTo(BeNil())
				Expect(set.GetName()).To(Equal("example.jp."))
				Expect(set.GetTTL()).To(Equal(uint32(300)))
				Expect(set.GetClass()).To(Equal(dns.Class(dns.ClassINET)))
				Expect(set.GetRRtype()).To(Equal(dns.TypeA))
				Expect(set.GetRRs()).To(Equal([]dns.RR{a11, a12}))
			})
		})
	})
	Context("test for GetName", func() {
		It("returns canonical name", func() {
			rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, nil)
			Expect(rrset.GetName()).To(Equal("example.jp."))
		})
	})
	Context("test for GetType", func() {
		It("returns uint16 rrtype", func() {
			rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, nil)
			Expect(rrset.GetRRtype()).To(Equal(dns.TypeA))
		})
	})
	Context("GetTTL", func() {
		It("returns uint32 TTL", func() {
			rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, nil)
			Expect(rrset.GetTTL()).To(Equal(uint32(300)))
		})
	})
	Context("SetTTL", func() {
		It("can set TTL", func() {
			a11 := MustNewRR("example.jp. 300 IN A 192.168.0.1")
			a12 := MustNewRR("example.jp. 300 IN A 192.168.0.2")
			rrset := dnsutils.NewRRSetFromRRs([]dns.RR{a11, a12})
			Expect(rrset.GetTTL()).To(Equal(uint32(300)))
			rrset.SetTTL(600)
			Expect(rrset.GetTTL()).To(Equal(uint32(600)))
			for _, rr := range rrset.GetRRs() {
				Expect(rr.Header().Ttl).To(Equal(uint32(600)))
			}
		})
	})
	Context("test for GetRRs", func() {
		It("returns RR slice", func() {
			rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{a11, a12})
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{a11, a12}))
		})
	})
	Context("test for AddRR", func() {
		var (
			rrset = dnsutils.NewRRSetFromRR(a11)
		)
		When("name ignore", func() {
			It("return err", func() {
				a2 := MustNewRR("example2.jp. 300 IN A 192.168.0.2")
				Expect(rrset.AddRR(a2)).NotTo(BeNil())
			})
		})
		When("ttl ignore", func() {
			It("return err", func() {
				a2 := MustNewRR("example.jp. 100 IN A 192.168.0.2")
				Expect(rrset.AddRR(a2)).NotTo(BeNil())
			})
		})
		When("class ignore", func() {
			It("return err", func() {
				ach := &dns.A{Hdr: dns.RR_Header{Name: "example.jp.", Class: dns.ClassCHAOS, Ttl: uint32(300), Rrtype: dns.TypeA}, A: net.ParseIP("192.168.0.2")}
				Expect(rrset.AddRR(ach)).NotTo(BeNil())
			})
		})
		When("type ignore", func() {
			It("return err", func() {
				Expect(rrset.AddRR(soa1)).NotTo(BeNil())
			})
		})
		It("name,ttl,type, or class ignore, returns nil", func() {
			Expect(dnsutils.NewRRSetFromRRs([]dns.RR{a11, soa1})).To(BeNil())
		})
		When("name,ttl,class,type is same value, and type is not CNAME,SOA", func() {
			It("can be add uniq RR", func() {
				rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, nil)
				err := rrset.AddRR(a11)
				Expect(err).To(Succeed())
				Expect(rrset.GetRRs()).To(Equal([]dns.RR{a11}))
				err = rrset.AddRR(a11)
				Expect(err).To(Succeed())
				Expect(rrset.GetRRs()).To(Equal([]dns.RR{a11}))
				err = rrset.AddRR(a12)
				Expect(err).To(Succeed())
				Expect(rrset.GetRRs()).To(Equal([]dns.RR{a11, a12}))
			})
		})
		When("type is SOA", func() {
			It("can not be add multiple RR (SOA)", func() {
				rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeSOA, []dns.RR{soa1})
				Expect(rrset.GetRRs()).To(Equal([]dns.RR{soa1}))

				err := rrset.AddRR(soa2)
				Expect(err).To(HaveOccurred())
				Expect(rrset.GetRRs()).To(Equal([]dns.RR{soa1}))
			})
		})
		When("type is CNAME", func() {
			It("can not be add multiple RR", func() {
				rrset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeCNAME,
					[]dns.RR{cname1})
				Expect(rrset.GetRRs()).To(Equal([]dns.RR{cname1}))

				err := rrset.AddRR(cname2)
				Expect(err).To(HaveOccurred())
				Expect(rrset.GetRRs()).To(Equal([]dns.RR{cname1}))
			})
		})
	})
	Context("test for RemoveRR", func() {
		It("can remove RR", func() {
			rrset := dnsutils.NewRRSetFromRRs([]dns.RR{a11, a12})
			Expect(rrset).NotTo(BeNil())
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{a11, a12}))
			rrset.RemoveRR(soa1)
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{a11, a12}))
			rrset.RemoveRR(a11)
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{a12}))
			rrset.RemoveRR(a12)
			Expect(rrset.GetRRs()).To(Equal([]dns.RR{}))
		})
	})
	Context("test for UnmarshalJSON", func() {
		var (
			err error
			set *dnsutils.RRSet
		)
		BeforeEach(func() {
			set = &dnsutils.RRSet{}
		})
		When("valid data", func() {
			BeforeEach(func() {
				jsonStr := []byte(`{"name": "example.jp", "class": "IN", "ttl": 300, "rrtype":"A","rdata": ["192.168.0.1","192.168.0.2"]}`)
				err = json.Unmarshal(jsonStr, set)
			})
			It("can parse json", func() {
				eset := dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{
					MustNewRR("example.jp. 300 IN A 192.168.0.1"),
					MustNewRR("example.jp. 300 IN A 192.168.0.2"),
				})
				Expect(err).To(Succeed())
				Expect(set).To(Equal(eset))
			})
		})
		When("invalid json (type invalid)", func() {
			BeforeEach(func() {
				jsonStr := []byte(`{"name": 0, "class": "IN", "ttl": 300, "rrtype":"A","rdata": ["2001:db8::1","192.168.0.2"]}`)
				err = json.Unmarshal(jsonStr, set)
			})
			It("return error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(MatchRegexp("failed to parse json format"))
			})
		})
		When("class invalid", func() {
			BeforeEach(func() {
				jsonStr := []byte(`{"name": "example.jp", "class": "HOGE", "ttl": 300, "rrtype":"A","rdata": ["2001:db8::1","192.168.0.2"]}`)
				err = json.Unmarshal(jsonStr, set)
			})
			It("return error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(MatchRegexp("invalid class"))
			})
		})
		When("ttl invalid", func() {
			BeforeEach(func() {
				jsonStr := []byte(`{"name": "example.jp", "class": "HOGE", "ttl": -1, "rrtype":"A","rdata": ["2001:db8::1","192.168.0.2"]}`)
				err = json.Unmarshal(jsonStr, set)
			})
			It("return error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(MatchRegexp("failed to parse json format"))
			})
		})
		When("not support rrtype", func() {
			BeforeEach(func() {
				jsonStr := []byte(`{"name": "example.jp", "class": "IN", "ttl": 300, "rrtype":"HOGE","rdata": ["2001:db8::1","192.168.0.2"]}`)
				err = json.Unmarshal(jsonStr, set)
			})
			It("return error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(MatchRegexp("not support rrtype"))
			})
		})
		When("empty rdata", func() {
			BeforeEach(func() {
				jsonStr := []byte(`{"name": "example.jp", "class": "IN", "ttl": 300, "rrtype":"A"}`)
				err = json.Unmarshal(jsonStr, set)
			})
			It("return error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(MatchRegexp("rdata must not be empty"))
			})
		})
		When("invalid rdata", func() {
			BeforeEach(func() {
				jsonStr := []byte(`{"name": "example.jp", "class": "IN", "ttl": 300, "rrtype":"A","rdata": ["2001:db8::1","192.168.0.2"]}`)
				err = json.Unmarshal(jsonStr, set)
			})
			It("return error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(MatchRegexp("failed to set Rdata"))
			})
		})
	})
	Context("test for MarshalJSON", func() {
		var (
			err error
			set *dnsutils.RRSet
			bs  []byte
		)
		BeforeEach(func() {
			set = dnsutils.NewRRSet("example.jp", 300, dns.ClassINET, dns.TypeA, []dns.RR{
				MustNewRR("example.jp. 300 IN A 192.168.0.1"),
				MustNewRR("example.jp. 300 IN A 192.168.0.2"),
			})
			bs, err = json.Marshal(set)
		})
		It("returns json string", func() {
			Expect(err).To(Succeed())
			Expect(bs).To(MatchJSON([]byte(`{"name": "example.jp.", "class": "IN", "ttl": 300, "rrtype":"A","rdata": ["192.168.0.1","192.168.0.2"]}`)))
		})
	})
})
