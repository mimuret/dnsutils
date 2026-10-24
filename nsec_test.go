package dnsutils_test

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
	"github.com/mimuret/dnsutils/testtool"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/sign/example.jp.nsec3.bind
var testNsec3SignedZone []byte

var _ = Describe("Test nsec.go", func() {
	var (
		err            error
		z              *dnsutils.Zone
		inception      = uint32(1704067200)
		expiration     = uint32(1893456000)
		nsecSignOption = dnsutils.SignOption{
			DoEMethod:      dnsutils.DenialOfExistenceMethodNSEC,
			Inception:      &inception,
			Expiration:     &expiration,
			ZONEMDEnabled:  &False,
			CDSEnabled:     &False,
			CDNSKEYEnabled: &False,
		}
		nsec3SignOption = dnsutils.SignOption{
			DoEMethod:      dnsutils.DenialOfExistenceMethodNSEC3,
			Inception:      &inception,
			Expiration:     &expiration,
			ZONEMDEnabled:  &False,
			CDSEnabled:     &False,
			CDNSKEYEnabled: &False,
		}
		zsk             *dnsutils.DNSKEY
		ksk             *dnsutils.DNSKEY
		dnskeys         []*dnsutils.DNSKEY
		nsecSignedZone  *dnsutils.Zone
		nsec3SignedZone *dnsutils.Zone
	)
	BeforeEach(func() {
		ksk, err = dnsutils.ReadDNSKEY(bytes.NewBuffer(testDnskeyED25519KSKPriv), bytes.NewBuffer(testDnskeyED25519KSKPub))
		Expect(err).To(Succeed())
		zsk, err = dnsutils.ReadDNSKEY(bytes.NewBuffer(testDnskeyED25519ZSKPriv), bytes.NewBuffer(testDnskeyED25519ZSKPub))
		Expect(err).To(Succeed())
		dnskeys = []*dnsutils.DNSKEY{ksk, zsk}

		nsecSignedZone = &dnsutils.Zone{}
		err = nsecSignedZone.Read(bytes.NewBuffer(testNsecSignedZone))
		Expect(err).To(Succeed())

		nsec3SignedZone = &dnsutils.Zone{}
		err = nsec3SignedZone.Read(bytes.NewBuffer(testNsec3SignedZone))
		Expect(err).To(Succeed())
	})
	It("can read ED25519 zsk/ksk", func() {
		Expect(ksk.GetRR().KeyTag()).To(Equal(uint16(2290)))
		Expect(ksk.GetSigner().Public())
		Expect(zsk.GetRR().KeyTag()).To(Equal(uint16(30075)))
	})
	Context("CreateDoE", func() {
		When("NSEC", func() {
			BeforeEach(func() {
				testZoneNormalBuf := bytes.NewBuffer(testSignZone)
				z = &dnsutils.Zone{}
				err = z.Read(testZoneNormalBuf)
				Expect(err).To(Succeed())
				err = dnsutils.CreateDoE(z, nsecSignOption, nil)
			})
			It("return success", func() {
				Expect(err).To(Succeed())
				var nsecRRs []dns.RR
				z.GetRootNode().IterateNameNode(func(nni dnsutils.NameNodeInterface) error {
					if nsecRRSet := nni.GetRRSet(dns.TypeNSEC); nsecRRSet != nil {
						nsecRRs = append(nsecRRs, nsecRRSet.GetRRs()...)
					}
					return nil
				})
				Expect(nsecRRs[0]).To(Equal(testtool.MustNewRR("example.jp. 300 IN NSEC \\000.example.jp. NS SOA RRSIG NSEC")))
				Expect(nsecRRs[1]).To(Equal(testtool.MustNewRR("\\000.example.jp. 300 IN NSEC *.example.jp. TXT RRSIG NSEC")))
				Expect(nsecRRs[2]).To(Equal(testtool.MustNewRR("*.example.jp. 300 IN NSEC test.hoge.example.jp. A RRSIG NSEC")))
				Expect(nsecRRs[3]).To(Equal(testtool.MustNewRR("test.hoge.example.jp. 300 IN NSEC www.hoge.example.jp. A RRSIG NSEC")))
				Expect(nsecRRs[4]).To(Equal(testtool.MustNewRR("www.hoge.example.jp. 300 IN NSEC sub1.example.jp. CNAME RRSIG NSEC")))
				Expect(nsecRRs[5]).To(Equal(testtool.MustNewRR("sub1.example.jp. 300 IN NSEC sub2.example.jp. NS DS RRSIG NSEC")))
				Expect(nsecRRs[6]).To(Equal(testtool.MustNewRR("sub2.example.jp. 300 IN NSEC example.jp. NS RRSIG NSEC")))
			})
			Context("Test for Sign with NSEC", func() {
				BeforeEach(func() {
					z = &dnsutils.Zone{}
					err = z.Read(bytes.NewBuffer(testSignZone))
					Expect(err).To(Succeed())
					err = dnsutils.AddDNSKEY(z, nsecSignOption, dnskeys, nil)
					Expect(err).To(Succeed())
					err = dnsutils.CreateDoE(z, nsecSignOption, nil)
					Expect(err).To(Succeed())
					err = dnsutils.SignZone(z, nsecSignOption, dnskeys, nil)
				})
				It("return success", func() {
					Expect(err).To(Succeed())
					Expect(dnsutils.IsEqualsAllTree(z.GetRootNode(), nsecSignedZone.GetRootNode(), false)).To(BeTrue())
				})
			})
		})
		When("NSEC3", func() {
			BeforeEach(func() {
				testZoneNormalBuf := bytes.NewBuffer(testSignZone)
				z = &dnsutils.Zone{}
				err = z.Read(testZoneNormalBuf)
				Expect(err).To(Succeed())
				err = dnsutils.CreateDoE(z, nsec3SignOption, nil)
			})
			It("return success", func() {
				Expect(err).To(Succeed())
				var nsec3RRs []dns.RR
				var nsec3params []dns.RR
				z.GetRootNode().IterateNameNode(func(nni dnsutils.NameNodeInterface) error {
					if nsec3RRSet := nni.GetRRSet(dns.TypeNSEC3); nsec3RRSet != nil {
						nsec3RRs = append(nsec3RRs, nsec3RRSet.GetRRs()...)
					}
					return nil
				})
				if nsec3paramRRSet := z.GetRootNode().GetRRSet(dns.TypeNSEC3PARAM); nsec3paramRRSet != nil {
					nsec3params = nsec3paramRRSet.GetRRs()
				}
				Expect(nsec3params).To(HaveLen(1))
				Expect(nsec3params[0]).To(Equal(testtool.MustNewRR("example.jp. 0 IN NSEC3PARAM 1 0 0 -")))
				Expect(nsec3RRs).To(HaveLen(8))
			})
			Context("Test for Sign with NSEC3", func() {
				BeforeEach(func() {
					z = &dnsutils.Zone{}
					err = z.Read(bytes.NewBuffer(testSignZone))
					Expect(err).To(Succeed())
					err = dnsutils.AddDNSKEY(z, nsec3SignOption, dnskeys, nil)
					Expect(err).To(Succeed())
					err = dnsutils.CreateDoE(z, nsec3SignOption, nil)
					Expect(err).To(Succeed())
					err = dnsutils.SignZone(z, nsec3SignOption, dnskeys, nil)
				})
				It("return success", func() {
					Expect(err).To(Succeed())
					Expect(dnsutils.IsEqualsAllTree(z.GetRootNode(), nsec3SignedZone.GetRootNode(), false)).To(BeTrue())
				})
			})
		})
	})
	Context("CreateDoE error handling", func() {
		When("DoEMethod is not supported", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(testSignZone))
				Expect(err).To(Succeed())
				err = dnsutils.CreateDoE(z, dnsutils.SignOption{DoEMethod: "HOGE"}, nil)
			})
			It("returns err", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("zone has no SOA", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(testSignZone))
				Expect(err).To(Succeed())
				Expect(z.GetRootNode().RemoveRRSet(dns.TypeSOA)).To(Succeed())
			})
			It("NSEC returns ErrBadZone", func() {
				Expect(dnsutils.CreateDoE(z, nsecSignOption, nil)).To(MatchError(dnsutils.ErrBadZone))
			})
			It("NSEC3 returns ErrBadZone", func() {
				Expect(dnsutils.CreateDoE(z, nsec3SignOption, nil)).To(MatchError(dnsutils.ErrBadZone))
			})
		})
		When("generator fails to create a rrset", func() {
			var generator *testtool.TestGenerator
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(testSignZone))
				Expect(err).To(Succeed())
				generator = &testtool.TestGenerator{NewRRSetErr: errors.New("boom")}
			})
			It("NSEC propagates the error", func() {
				Expect(dnsutils.CreateDoE(z, nsecSignOption, generator)).To(HaveOccurred())
			})
			It("NSEC3 propagates the error", func() {
				Expect(dnsutils.CreateDoE(z, nsec3SignOption, generator)).To(HaveOccurred())
			})
		})
	})
	Context("Empty Non-Terminal (ENT) handling", func() {
		// only a.b.c.example.jp. holds data, so b.c.example.jp. and
		// c.example.jp. exist in the tree solely as empty non-terminals.
		entZone := []byte(`example.jp. 3600 IN SOA localhost. root.localhost. 1 3600 900 85400 300
example.jp. 3600 IN NS ns1.example.com.
a.b.c.example.jp. 3600 IN A 192.0.2.1
`)
		When("NSEC", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(entZone))
				Expect(err).To(Succeed())
				err = dnsutils.CreateDoE(z, nsecSignOption, nil)
			})
			It("does not create NSEC records for ENT owner names, and the chain skips over them", func() {
				Expect(err).To(Succeed())
				for _, name := range []string{"c.example.jp.", "b.c.example.jp."} {
					nni, ok := z.GetRootNode().GetNameNode(name)
					Expect(ok).To(BeTrue())
					Expect(nni.GetRRSet(dns.TypeNSEC)).To(BeNil())
				}
				var nsecCount int
				z.GetRootNode().IterateNameNode(func(nni dnsutils.NameNodeInterface) error {
					if set := nni.GetRRSet(dns.TypeNSEC); set != nil {
						nsecCount += len(set.GetRRs())
					}
					return nil
				})
				Expect(nsecCount).To(Equal(2))
				apexNsec := z.GetRootNode().GetRRSet(dns.TypeNSEC).GetRRs()[0].(*dns.NSEC)
				Expect(apexNsec.NextDomain).To(Equal("a.b.c.example.jp."))
			})
		})
		When("NSEC3", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(entZone))
				Expect(err).To(Succeed())
				err = dnsutils.CreateDoE(z, nsec3SignOption, nil)
			})
			It("creates NSEC3 records for ENT owner names, with an empty type bitmap", func() {
				Expect(err).To(Succeed())
				var total, emptyBitmaps int
				z.GetRootNode().IterateNameNode(func(nni dnsutils.NameNodeInterface) error {
					if set := nni.GetRRSet(dns.TypeNSEC3); set != nil {
						for _, rr := range set.GetRRs() {
							total++
							if len(rr.(*dns.NSEC3).TypeBitMap) == 0 {
								emptyBitmaps++
							}
						}
					}
					return nil
				})
				// apex, a.b.c.example.jp. (real data), and the 2 ENTs.
				Expect(total).To(Equal(4))
				Expect(emptyBitmaps).To(Equal(2))
			})
		})
	})
	Context("NSEC3 bitmap for secure vs insecure delegations", func() {
		BeforeEach(func() {
			z = &dnsutils.Zone{}
			err = z.Read(bytes.NewBuffer(testSignZone))
			Expect(err).To(Succeed())
			err = dnsutils.CreateDoE(z, nsec3SignOption, nil)
			Expect(err).To(Succeed())
		})
		hashedOwner := func(name string) string {
			hash := dns.HashName(name, dns.SHA1, nsec3SignOption.GetNSEC3Iterate(), nsec3SignOption.GetNSEC3Salt())
			return dns.CanonicalName(hash + ".example.jp.")
		}
		It("includes DS and RRSIG for the secure delegation (sub1, has DS)", func() {
			nni, ok := z.GetRootNode().GetNameNode(hashedOwner("sub1.example.jp."))
			Expect(ok).To(BeTrue())
			rr := nni.GetRRSet(dns.TypeNSEC3).GetRRs()[0].(*dns.NSEC3)
			Expect(rr.TypeBitMap).To(ConsistOf(dns.TypeNS, dns.TypeDS, dns.TypeRRSIG))
		})
		It("omits RRSIG for the insecure delegation (sub2, no DS)", func() {
			nni, ok := z.GetRootNode().GetNameNode(hashedOwner("sub2.example.jp."))
			Expect(ok).To(BeTrue())
			rr := nni.GetRRSet(dns.TypeNSEC3).GetRRs()[0].(*dns.NSEC3)
			Expect(rr.TypeBitMap).To(ConsistOf(dns.TypeNS))
		})
		It("does not create a NSEC3 record for glue-only names", func() {
			for _, name := range []string{"ns.sub1.example.jp.", "ns.sub2.example.jp."} {
				_, ok := z.GetRootNode().GetNameNode(hashedOwner(name))
				Expect(ok).To(BeFalse())
			}
		})
	})
	Context("QNAME length boundary (RFC1035 255 octet limit)", func() {
		// dns.IsDomainName (as vendored here) accepts names up to 257 wire
		// octets, two more than RFC1035's 255 octet limit that dnsutils.Equals
		// actually enforces (it packs names into a fixed 255-byte buffer), so
		// the wire-format pack result is used as the oracle instead.
		validWireLength := func(name string) bool {
			buf := make([]byte, 255)
			_, err := dns.PackDomainName(name, buf, 0, nil, false)
			return err == nil
		}
		// builds the longest name that is still valid directly under example.jp.
		buildMaxLengthName := func() string {
			label63 := strings.Repeat("a", 63)
			name := "example.jp."
			for {
				candidate := label63 + "." + name
				if !validWireLength(candidate) {
					break
				}
				name = candidate
			}
			for l := 62; l >= 1; l-- {
				candidate := strings.Repeat("a", l) + "." + name
				if validWireLength(candidate) {
					name = candidate
					break
				}
			}
			return name
		}
		When("a name at the maximum valid length (255 octets) exists in the zone", func() {
			var longName string
			BeforeEach(func() {
				longName = buildMaxLengthName()
				// one label longer must be rejected, confirming longName really sits on the boundary.
				Expect(validWireLength("x." + longName)).To(BeFalse())

				zoneData := fmt.Sprintf(
					"example.jp. 3600 IN SOA localhost. root.localhost. 1 3600 900 85400 300\n"+
						"example.jp. 3600 IN NS ns1.example.com.\n"+
						"%s 3600 IN A 192.0.2.1\n", longName)
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer([]byte(zoneData)))
				Expect(err).To(Succeed())
			})
			It("signs NSEC zones without error", func() {
				Expect(dnsutils.AddDNSKEY(z, nsecSignOption, dnskeys, nil)).To(Succeed())
				Expect(dnsutils.CreateDoE(z, nsecSignOption, nil)).To(Succeed())
				Expect(dnsutils.SignZone(z, nsecSignOption, dnskeys, nil)).To(Succeed())
				nni, ok := z.GetRootNode().GetNameNode(longName)
				Expect(ok).To(BeTrue())
				Expect(nni.GetRRSet(dns.TypeNSEC)).NotTo(BeNil())
				Expect(nni.GetRRSet(dns.TypeRRSIG)).NotTo(BeNil())
			})
			// github.com/miekg/dns v1.1.56 panicked here: dns.HashName packed
			// the name into a fixed 255-byte buffer and then sliced one byte
			// past it ("slice bounds out of range [:256] with capacity 255")
			// for any owner name that is exactly 255 wire octets long, because
			// dns.PackDomainName itself could overrun a buffer sized exactly
			// to the name's length without returning an error. Fixed upstream
			// by v1.1.73 (see go.mod); this now signs cleanly.
			It("signs NSEC3 zones without error", func() {
				Expect(dnsutils.AddDNSKEY(z, nsec3SignOption, dnskeys, nil)).To(Succeed())
				Expect(dnsutils.CreateDoE(z, nsec3SignOption, nil)).To(Succeed())
				Expect(dnsutils.SignZone(z, nsec3SignOption, dnskeys, nil)).To(Succeed())
			})
		})
		When("the zone apex itself is long enough that its hashed NSEC3 owner name would overflow 255 octets", func() {
			BeforeEach(func() {
				// 3 labels of 63 octets + 1 label of 32 octets => a 226 octet
				// wire-format apex name, which is itself valid. But prefixing
				// a 32-char base32 SHA1 hash label (+ length octet) to build
				// its own NSEC3 owner name pushes that name to 258 octets,
				// which is no longer a valid domain name.
				label63 := strings.Repeat("a", 63)
				label32 := strings.Repeat("b", 32)
				overflowApex := strings.Join([]string{label63, label63, label63, label32}, ".") + "."
				_, ok := dns.IsDomainName(overflowApex)
				Expect(ok).To(BeTrue())

				zoneData := fmt.Sprintf("%s 3600 IN SOA localhost. root.localhost. 1 3600 900 85400 300\n", overflowApex)
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer([]byte(zoneData)))
				Expect(err).To(Succeed())
			})
			It("NSEC still succeeds, since it never hashes owner names", func() {
				err = dnsutils.CreateDoE(z, dnsutils.SignOption{DoEMethod: dnsutils.DenialOfExistenceMethodNSEC}, nil)
				Expect(err).To(Succeed())
			})
			It("NSEC3 fails cleanly instead of producing an invalid owner name", func() {
				err = dnsutils.CreateDoE(z, dnsutils.SignOption{DoEMethod: dnsutils.DenialOfExistenceMethodNSEC3}, nil)
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
