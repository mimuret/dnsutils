package ddns_test

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/mimuret/dnsutils"
	"github.com/mimuret/dnsutils/ddns"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func MustNewRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

//go:embed tests/example.jp
var zonefile []byte

var _ ddns.UpdateInterface = &TestUpdate{}

type TestUpdate struct {
	addRRs         []dns.RR
	replaceRRSet   []dnsutils.RRSetInterface
	removeZoneApex bool
	removeName     []string
	removeRRSet    map[string][]uint16
	removeRR       []dns.RR
}

func NewTestUpdate() *TestUpdate {
	return &TestUpdate{
		addRRs:       []dns.RR{},
		replaceRRSet: []dnsutils.RRSetInterface{},
		removeName:   []string{},
		removeRRSet:  map[string][]uint16{},
		removeRR:     []dns.RR{},
	}
}

func (u *TestUpdate) GetZone(*dns.Msg) (dnsutils.ZoneInterface, error) {
	buf := bytes.NewBuffer(zonefile)
	zone := dnsutils.NewZone("example.jp", dns.ClassINET)
	if err := zone.Read(buf); err != nil {
		return nil, err
	}
	return zone, nil
}

func (u *TestUpdate) AddRR(rr dns.RR) error {
	u.addRRs = append(u.addRRs, rr)
	return nil
}
func (u *TestUpdate) ReplaceRRSet(set dnsutils.RRSetInterface) error {
	u.replaceRRSet = append(u.replaceRRSet, set)
	return nil
}

// remove zone apex name rr other than SOA,NS
func (u *TestUpdate) RemoveNameApex(name string) error {
	u.removeZoneApex = true
	return nil
}

// remove name rr ignore SOA, NS
func (u *TestUpdate) RemoveName(name string) error {
	u.removeName = append(u.removeName, name)
	return nil
}

// remove name rr ignore SOA, NS
func (u *TestUpdate) RemoveRRSet(name string, rrtype uint16) error {
	u.removeRRSet[name] = append(u.removeRRSet[name], rrtype)
	return nil
}

// remove name rr ignore SOA, NS
func (u *TestUpdate) RemoveRR(rr dns.RR) error {
	u.removeRR = append(u.removeRR, rr)
	return nil
}

func (u *TestUpdate) IsPrecheckSupportedRtype(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeANY, dns.TypeNone, dns.TypeSOA, dns.TypeA, dns.TypeAAAA, dns.TypeCAA, dns.TypeCNAME,
		dns.TypeDS, dns.TypeNS, dns.TypeMX, dns.TypeNAPTR,
		dns.TypeSRV, dns.TypeTXT, dns.TypeTLSA, dns.TypePTR:
		return true

	}
	return false
}
func (u *TestUpdate) IsUpdateSupportedRtype(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeSOA, dns.TypeA, dns.TypeAAAA, dns.TypeCAA, dns.TypeCNAME,
		dns.TypeDS, dns.TypeNS, dns.TypeMX, dns.TypeNAPTR,
		dns.TypeSRV, dns.TypeTXT, dns.TypeTLSA, dns.TypePTR:
		return true

	}
	return false
}

func (t *TestUpdate) UpdateFailedPostProcess(error) {}
func (t *TestUpdate) UpdatePostProcess() error      { return nil }

func TestDDNS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ddns Suite")
}

var _ = Describe("DDNS", func() {
	var (
		d    *ddns.DDNS
		gi   *TestUpdate
		ui   *TestUpdate
		zone dnsutils.ZoneInterface
		msg  *dns.Msg
	)
	BeforeEach(func() {
		var err error
		msg = &dns.Msg{}
		msg.SetUpdate("example.jp")
		gi = NewTestUpdate()
		ui = NewTestUpdate()
		d = ddns.NewDDNS(ui)
		zone, err = gi.GetZone(msg)
		if err != nil {
			panic(err)
		}
	})
	Context("NewDDNS", func() {
		When("UpdateInterface is nil", func() {
			It("returns nil", func() {
				Expect(ddns.NewDDNS(nil)).To(BeNil())
			})
		})
	})
	Context("Test for DDNS.CheckZoneSection", func() {
		It("can not request multiple zone section records", func() {
			msg.Question = append(msg.Question, dns.Question{Name: "example.jp.", Qtype: dns.TypeSOA, Qclass: dns.ClassINET})
			rc := d.CheckZoneSection(zone, msg)
			Expect(rc).To(Equal(dns.RcodeFormatError))
		})
		It("can not request that ztype is not soa", func() {
			msg.Question = []dns.Question{{Name: "example.jp.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
			rc := d.CheckZoneSection(zone, msg)
			Expect(rc).To(Equal(dns.RcodeFormatError))
		})
		It("can not request that zname is not equals to zone name", func() {
			msg.SetUpdate("www.example.jp.")
			rc := d.CheckZoneSection(zone, msg)
			Expect(rc).To(Equal(dns.RcodeNotAuth))
		})
		It("can request ztype=SOA zname=zone name", func() {
			rc := d.CheckZoneSection(zone, msg)
			Expect(rc).To(Equal(dns.RcodeSuccess))
		})
	})
	Context("Test for DDNS.PrerequisiteProessing", func() {
		When("request is format error", func() {
			It("can not request unsupported rtype", func() {
				msg.Answer = []dns.RR{MustNewRR("example.jp. 0 IN DNSKEY 256 3 8 AwEAAb6AguVDdiFFs84nDYA6sIXMG3E0Y6QJm98IUH60hfoltGvvkFh9 QMWG2wrqYUhUWvWYXW9gXfeWRCgay/FgrnKjcvAErFmv3dPT81E8jEQc Q7uUlpoIxs/8oVGG1jY1qZJINxwWsF0vm3xx6fnGSwelOCKoRuawo4U4 +TWiO9wf")}
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNotImplemented))
			})
			It("can not request that ttl not zero", func() {
				msg.Answer = []dns.RR{MustNewRR("example.jp. 3600 IN A 172.16.0.1")}
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeFormatError))
			})
			It("can not request that name is not zone", func() {
				msg.Answer = []dns.RR{MustNewRR("example2.jp. 0 IN A 172.16.0.1")}
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNotZone))
				msg.Answer = []dns.RR{MustNewRR("jp. 0 IN A 172.16.0.1")}
				rc = d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNotZone))
			})
		})
		When("request is exist check", func() {
			It("can not request that rdlength not zero", func() {
				msg.Answer = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeANY, Class: dns.ClassANY, Rdlength: 1}}}
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeFormatError))
			})
			It("can pre check that exist name (exist name)", func() {
				msg.NameUsed([]dns.RR{MustNewRR("example.jp. 0 IN A 172.16.0.1")})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeSuccess))
			})
			It("can pre check that exist name (not exist name)", func() {
				msg.NameUsed([]dns.RR{MustNewRR("notexist.example.jp. 0 IN A 172.16.0.1")})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNameError))
			})
			It("can pre check that exist rrset(exist rrset)", func() {
				msg.RRsetUsed([]dns.RR{MustNewRR("example.jp. 0 IN NS localhost.")})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeSuccess))
			})
			It("can pre check that exist rrset(name exist, rrset not exist)", func() {
				msg.RRsetUsed([]dns.RR{MustNewRR(`example.jp. 0 IN TXT "hoge"`)})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNXRrset))
			})
			It("can pre check that exist rrset(name not exist)", func() {
				msg.RRsetUsed([]dns.RR{MustNewRR(`notexist.example.jp. 0 IN TXT "hoge"`)})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNXRrset))
			})
		})
		When("request is not exist check", func() {
			It("can not request that rdlength not zero", func() {
				msg.Answer = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeANY, Class: dns.ClassNONE, Rdlength: 1}}}
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeFormatError))
			})
			It("can pre check that not exist name(exist name)", func() {
				msg.NameNotUsed([]dns.RR{MustNewRR("example.jp. 0 IN A 172.16.0.1")})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeYXDomain))
				msg.Answer = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeANY, Class: dns.ClassNONE}}}
				rc = d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeYXDomain))
			})
			It("can pre check that not exist name (not exist name)", func() {
				msg.NameNotUsed([]dns.RR{MustNewRR("notexist.example.jp. 0 IN A 172.16.0.1")})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeSuccess))
			})
			It("can pre check that not exist rrset(exist rrset)", func() {
				msg.RRsetNotUsed([]dns.RR{MustNewRR("example.jp. 0 IN NS localhost.")})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeYXRrset))
			})
			It("can pre check that not exist rrset(name exist, rrset not exist)", func() {
				msg.RRsetNotUsed([]dns.RR{MustNewRR(`example.jp. 0 IN TXT "hoge"`)})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeSuccess))
			})
			It("can pre check that not exist rrset(name not exist)", func() {
				msg.RRsetNotUsed([]dns.RR{MustNewRR(`notexist.example.jp. 0 IN TXT "hoge"`)})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeSuccess))
			})
		})
		When("request is exist rdata check", func() {
			It("can pre check that rr exist (name not exist", func() {
				msg.Used([]dns.RR{MustNewRR(`notexist.example.jp. 0 IN TXT "hoge"`)})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNXRrset))
			})
			It("can pre check that rr exist (rrset not exist", func() {
				msg.Used([]dns.RR{MustNewRR(`example.jp. 0 IN TXT "hoge"`)})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNXRrset))
			})
			It("can pre check that rr exist (rrset exist, rr not exist", func() {
				msg.Used([]dns.RR{MustNewRR(`example.jp. 0 IN NS ns3.example.net.`)})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNXRrset))
			})
			It("can pre check that rr exist (rrset exist, rdata not equals", func() {
				msg.Used([]dns.RR{
					MustNewRR(`example.jp. 0 IN NS ns1.example.jp.`),
				})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNXRrset))
			})
			It("can pre check that rr exist (rrset exist, rdata equals", func() {
				msg.Used([]dns.RR{
					MustNewRR(`example.jp. 0 IN NS ns1.example.jp.`),
					MustNewRR(`example.jp. 0 IN NS ns2.example.jp.`),
				})
				rc := d.PrerequisiteProessing(zone, msg)
				Expect(rc).To(Equal(dns.RcodeSuccess))
			})
		})
	})
	Context("Test for DDNS.UpdatePrescan", func() {
		When("request rtype is not supported", func() {
			It("returns rcode formerror", func() {
				msg.Insert([]dns.RR{MustNewRR("example.jp. 3600 IN DNSKEY 256 3 8 AwEAAb6AguVDdiFFs84nDYA6sIXMG3E0Y6QJm98IUH60hfoltGvvkFh9 QMWG2wrqYUhUWvWYXW9gXfeWRCgay/FgrnKjcvAErFmv3dPT81E8jEQc Q7uUlpoIxs/8oVGG1jY1qZJINxwWsF0vm3xx6fnGSwelOCKoRuawo4U4 +TWiO9wf")})
				rc := d.UpdatePrescan(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNotImplemented))
			})
		})
		When("request name is not zone domain name", func() {
			It("returns rcode NotZone", func() {
				msg.Ns = []dns.RR{MustNewRR("example2.jp. 0 IN A 172.16.0.1")}
				rc := d.UpdatePrescan(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNotZone))
				msg.Ns = []dns.RR{MustNewRR("jp. 0 IN A 172.16.0.1")}
				rc = d.UpdatePrescan(zone, msg)
				Expect(rc).To(Equal(dns.RcodeNotZone))
			})
		})
		When("request is Add To An RRset (rfc2136 2.5.1)", func() {
			When("request rtype is invalid", func() {
				It("returns rcode formerror", func() {
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeAXFR, Class: dns.ClassINET, Rdlength: 0}}}
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeMAILA, Class: dns.ClassINET, Rdlength: 0}}}
					rc = d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeMAILB, Class: dns.ClassINET, Rdlength: 0}}}
					rc = d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
				})
			})
			When("request is normal query", func() {
				It("returns rcode NoError", func() {
					msg.Ns = []dns.RR{MustNewRR("example.jp. 3600 IN A 192.168.0.1")}
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeSuccess))
				})
			})
		})
		When("request is Delete An RRset (rfc2136 2.5.2)", func() {
			When("request ttl is not zero", func() {
				It("returns rcode formerror", func() {
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 30, Rrtype: dns.TypeANY, Class: dns.ClassANY, Rdlength: 0}}}
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
				})
			})
			When("request Rdlength is not zero", func() {
				It("returns rcode formerror", func() {
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeANY, Class: dns.ClassANY, Rdlength: 1}}}
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
				})
			})
			When("request is normal query zone apex", func() {
				It("returns rcode NoError", func() {
					msg.RemoveName([]dns.RR{MustNewRR("example.jp. 3600 IN A 192.168.0.1")})
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeSuccess))
				})
			})
			When("request is normal query", func() {
				It("returns rcode NoError", func() {
					msg.RemoveName([]dns.RR{MustNewRR("mail.example.jp 3600 IN A 192.168.0.1")})
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeSuccess))
				})
			})
		})
		When("request is Delete All RRsets From A Name (rfc2136 2.5.3)", func() {
			When("request rtype is invalid", func() {
				It("returns rcode formerror", func() {
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeAXFR, Class: dns.ClassANY, Rdlength: 0}}}
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeMAILA, Class: dns.ClassANY, Rdlength: 0}}}
					rc = d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeMAILB, Class: dns.ClassANY, Rdlength: 0}}}
					rc = d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
				})
			})
			When("request Rdlength is not zero", func() {
				It("returns rcode formerror", func() {
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeA, Class: dns.ClassANY, Rdlength: 1}}}
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
				})
			})
			When("request is normal query", func() {
				It("returns rcode NoError", func() {
					msg.RemoveRRset([]dns.RR{MustNewRR("example.jp. 3600 IN A 192.168.0.1")})
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeSuccess))
				})
			})
		})
		When("request is Delete An RR From An RRset (rfc2136 2.5.4)", func() {
			When("request rtype is invalid", func() {
				It("returns rcode formerror", func() {
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeAXFR, Class: dns.ClassNONE, Rdlength: 0}}}
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeMAILA, Class: dns.ClassNONE, Rdlength: 0}}}
					rc = d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 0, Rrtype: dns.TypeMAILB, Class: dns.ClassNONE, Rdlength: 0}}}
					rc = d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
				})
			})
			When("request ttl is not zero", func() {
				It("returns rcode formerror", func() {
					msg.Ns = []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.jp.", Ttl: 30, Rrtype: dns.TypeA, Class: dns.ClassNONE, Rdlength: 0}}}
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeFormatError))
				})
			})
			When("request is normal query", func() {
				It("returns rcode NoError", func() {
					msg.Remove([]dns.RR{MustNewRR("example.jp. 3600 IN A 192.168.0.1")})
					rc := d.UpdatePrescan(zone, msg)
					Expect(rc).To(Equal(dns.RcodeSuccess))
				})
			})
		})
	})
	Context("Test for DDNS.UpdateProcessing", func() {
		Context("Add To An RRset", func() {
			When("add CNAME", func() {
				When("name exist other type", func() {
					It("not changed", func() {
						rrs := []dns.RR{MustNewRR("example.jp. 300 IN CNAME www.example.net.")}
						msg.Insert(rrs)
						err := d.UpdateProcessing(zone, msg)
						Expect(err).To(BeNil())
						Expect(ui.addRRs).To(Equal([]dns.RR{}))
					})
				})
				When("cname replace", func() {
					It("replaced", func() {
						rr := MustNewRR("www.example.jp. 300 IN CNAME www.example.org.")
						rrset := dnsutils.NewRRSetFromRR(rr)
						msg.Insert([]dns.RR{rr})
						err := d.UpdateProcessing(zone, msg)
						Expect(err).To(BeNil())
						Expect(ui.replaceRRSet).To(Equal([]dnsutils.RRSetInterface{rrset}))
					})
				})
				When("name not exist", func() {
					It("add", func() {
						rr := MustNewRR("notexist.example.jp. 300 IN CNAME www.example.org.")
						msg.Insert([]dns.RR{rr})
						err := d.UpdateProcessing(zone, msg)
						Expect(err).To(BeNil())
						Expect(ui.addRRs).To(Equal([]dns.RR{rr}))
					})
				})
			})
			When("add SOA", func() {
				When("cname replace", func() {
					It("replaced", func() {
						rr := MustNewRR("example.jp. 3600 IN SOA localhost. root.localost. 2 3600 900 85400 300")
						rrset := dnsutils.NewRRSetFromRR(rr)
						msg.Insert([]dns.RR{rr})
						err := d.UpdateProcessing(zone, msg)
						Expect(err).To(BeNil())
						Expect(ui.replaceRRSet).To(Equal([]dnsutils.RRSetInterface{rrset}))
					})
				})
			})
			When("other rrtype", func() {
				When("name exist CNAME type", func() {
					It("not changed", func() {
						rrs := []dns.RR{MustNewRR("www.example.jp. 300 IN A 192.168.0.1")}
						msg.Insert(rrs)
						err := d.UpdateProcessing(zone, msg)
						Expect(err).To(BeNil())
						Expect(ui.addRRs).To(Equal([]dns.RR{}))
					})
				})
				When("name not exist CNAME type", func() {
					It("add rr", func() {
						rrs := []dns.RR{MustNewRR("example.jp. 300 IN A 192.168.0.1")}
						msg.Insert(rrs)
						err := d.UpdateProcessing(zone, msg)
						Expect(err).To(BeNil())
						Expect(ui.addRRs).To(Equal(rrs))
					})
				})
			})
		})
		Context("Delete An RRset", func() {
			It("remove rrset", func() {
				rrs := []dns.RR{
					MustNewRR("www.example.jp. 300 IN CNAME www.example.net."),
					MustNewRR("ns1.example.jp. 300 IN A 192.168.0.1"),
					MustNewRR("ns1.example.jp. 300 IN A 192.168.0.2"),
				}
				msg.RemoveRRset(rrs)
				err := d.UpdateProcessing(zone, msg)
				Expect(err).To(BeNil())
				Expect(ui.removeRRSet).To(Equal(map[string][]uint16{
					"www.example.jp.": {
						dns.TypeCNAME,
					},
					"ns1.example.jp.": {
						dns.TypeA,
						dns.TypeA,
					},
				}))
			})
		})
		Context("Delete all RRsets from a name", func() {
			It("remove name", func() {
				rrs := []dns.RR{
					MustNewRR("www.example.jp. 300 IN CNAME www.example.net."),
					MustNewRR("ns1.example.jp. 300 IN A 192.168.0.1"),
					MustNewRR("ns1.example.jp. 300 IN A 192.168.0.2"),
				}
				msg.RemoveName(rrs)
				err := d.UpdateProcessing(zone, msg)
				Expect(err).To(BeNil())
				Expect(ui.removeName).To(Equal([]string{"www.example.jp.", "ns1.example.jp.", "ns1.example.jp."}))
			})
		})
		Context("Delete an RR from an RRset", func() {
			It("remove rr", func() {
				rrs := []dns.RR{
					MustNewRR("www.example.jp. 300 IN CNAME www.example.net."),
					MustNewRR("ns1.example.jp. 300 IN A 192.168.0.1"),
					MustNewRR("ns1.example.jp. 300 IN A 192.168.0.2"),
				}
				msg.Remove(rrs)
				err := d.UpdateProcessing(zone, msg)
				Expect(err).To(BeNil())
				Expect(ui.removeRR).To(Equal(rrs))
			})
		})
	})
})
