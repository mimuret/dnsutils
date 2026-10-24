package dnsutils_test

import (
	"bytes"
	_ "embed"
	"errors"
	"time"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
	"github.com/mimuret/dnsutils/testtool"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var True = true
var False = false

//go:embed testdata/sign/example.jp.source
var testSignZone []byte

//go:embed testdata/sign/example.jp.nsec.bind
var testNsecSignedZone []byte

//go:embed testdata/sign/keys/Kexample.jp.+015+02290.private
var testDnskeyED25519KSKPriv []byte

//go:embed testdata/sign/keys/Kexample.jp.+015+02290.key
var testDnskeyED25519KSKPub []byte

//go:embed testdata/sign/keys/Kexample.jp.+015+30075.private
var testDnskeyED25519ZSKPriv []byte

//go:embed testdata/sign/keys/Kexample.jp.+015+30075.key
var testDnskeyED25519ZSKPub []byte

var _ = Describe("Test sign.go", func() {
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
		zsk              *dnsutils.DNSKEY
		ksk              *dnsutils.DNSKEY
		dnskeys          []*dnsutils.DNSKEY
		nsec_signed_zone *dnsutils.Zone
	)
	BeforeEach(func() {
		ksk, err = dnsutils.ReadDNSKEY(bytes.NewBuffer(testDnskeyED25519KSKPriv), bytes.NewBuffer(testDnskeyED25519KSKPub))
		Expect(err).To(Succeed())
		zsk, err = dnsutils.ReadDNSKEY(bytes.NewBuffer(testDnskeyED25519ZSKPriv), bytes.NewBuffer(testDnskeyED25519ZSKPub))
		Expect(err).To(Succeed())
		dnskeys = []*dnsutils.DNSKEY{ksk, zsk}

		nsec_signed_zone = &dnsutils.Zone{}
		err = nsec_signed_zone.Read(bytes.NewBuffer(testNsecSignedZone))
		Expect(err).To(Succeed())
	})
	It("can read ED25519 zsk/ksk", func() {
		Expect(ksk.GetRR().KeyTag()).To(Equal(uint16(2290)))
		Expect(ksk.GetSigner().Public())
		Expect(zsk.GetRR().KeyTag()).To(Equal(uint16(30075)))
	})
	Context("SignOption", func() {
		var (
			signOpt               dnsutils.SignOption
			beforeSign            time.Duration
			expiry                time.Duration
			inception, expiration uint32
		)
		When("default", func() {
			Context("GetBeforSign", func() {
				BeforeEach(func() {
					signOpt = dnsutils.SignOption{}
					dnsutils.DefaultBeforeSign = time.Hour * 2
					beforeSign = signOpt.GetBeforSign()
				})
				AfterEach(func() {
					dnsutils.DefaultBeforeSign = time.Hour
				})
				It("returns 2 hour", func() {
					Expect(beforeSign).To(Equal(time.Hour * 2))
				})
			})
			Context("GetExpiry", func() {
				BeforeEach(func() {
					signOpt = dnsutils.SignOption{}
					dnsutils.DefaultExpiry = time.Hour * 30
					expiry = signOpt.GetExpiry()
				})
				AfterEach(func() {
					dnsutils.DefaultExpiry = time.Hour * 24 * 14
				})
				It("returns an hour", func() {
					Expect(expiry).To(Equal(time.Hour * 30))
				})
			})
			Context("GetInception", func() {
				BeforeEach(func() {
					signOpt = dnsutils.SignOption{}
					inception = signOpt.GetInception()
				})
				It("returns last hour", func() {
					u := time.Now().UTC().Add(-time.Hour).Unix()
					Expect(inception).To(BeNumerically("~", u-60, u))
				})
			})
			Context("GetExpiration", func() {
				BeforeEach(func() {
					signOpt = dnsutils.SignOption{}
					expiration = signOpt.GetExpiration()
				})
				It("returns 2 weeks later", func() {
					u := time.Now().UTC().Add(dnsutils.DefaultExpiry).Unix()
					Expect(expiration).To(BeNumerically("~", u-60, u))
				})
			})
		})
	})
	Context("ReadDNSKEY", func() {
		var (
			dnskey *dnsutils.DNSKEY
			err    error
		)
		When("no have DNSKEY", func() {
			BeforeEach(func() {
				dnskey, err = dnsutils.ReadDNSKEY(bytes.NewBuffer(testDnskeyED25519KSKPriv), bytes.NewBuffer(testSignZone))
			})
			It("return err", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("no have privateKey", func() {
			BeforeEach(func() {
				dnskey, err = dnsutils.ReadDNSKEY(bytes.NewBuffer([]byte{}), bytes.NewBuffer(testDnskeyED25519KSKPub))
			})
			It("return err", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("valid data", func() {
			BeforeEach(func() {
				dnskey, err = dnsutils.ReadDNSKEY(bytes.NewBuffer(testDnskeyED25519KSKPriv), bytes.NewBuffer(testDnskeyED25519KSKPub))
			})
			It("return err", func() {
				Expect(err).To(Succeed())
				Expect(dnskey).NotTo(BeNil())
			})
		})
	})
	Context("AddDNSKEY", func() {
		var (
			err error
			z   *dnsutils.Zone
		)
		BeforeEach(func() {
			z = &dnsutils.Zone{}
			err = z.Read(bytes.NewBuffer(testSignZone))
			Expect(err).To(Succeed())
		})
		When("empty key", func() {
			BeforeEach(func() {
				err = dnsutils.AddDNSKEY(z, dnsutils.SignOption{}, nil, nil)
			})
			It("returns err", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("failed to create DNSKEY rrset", func() {
			BeforeEach(func() {
				err = dnsutils.AddDNSKEY(z, dnsutils.SignOption{}, nil, &testtool.TestGenerator{NewRRSetErr: errors.New("")})
			})
			It("returns err", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("add valid DNSKEY", func() {
			When("cds/cdnskey disabled", func() {
				BeforeEach(func() {
					err = dnsutils.AddDNSKEY(z, dnsutils.SignOption{CDSEnabled: &False, CDNSKEYEnabled: &False}, []*dnsutils.DNSKEY{ksk}, nil)
				})
				It("succeed", func() {
					Expect(err).To(Succeed())
					cdsRRSet := z.GetRootNode().GetRRSet(dns.TypeCDS)
					Expect(cdsRRSet).To(BeNil())
					cdnskeyRRSet := z.GetRootNode().GetRRSet(dns.TypeCDNSKEY)
					Expect(cdnskeyRRSet).To(BeNil())
				})
			})
			When("cds/cdnskey enabled", func() {
				BeforeEach(func() {
					err = dnsutils.AddDNSKEY(z, dnsutils.SignOption{}, []*dnsutils.DNSKEY{ksk}, nil)
				})
				It("succeed", func() {
					Expect(err).To(Succeed())
					cdsRRSet := z.GetRootNode().GetRRSet(dns.TypeCDS)
					Expect(cdsRRSet).NotTo(BeNil())
					cdnskeyRRSet := z.GetRootNode().GetRRSet(dns.TypeCDNSKEY)
					Expect(cdnskeyRRSet).NotTo(BeNil())
				})
			})
		})
	})
	Context("Test for Sign", func() {
		BeforeEach(func() {
			testZoneNormalBuf := bytes.NewBuffer(testSignZone)
			z = &dnsutils.Zone{}
			err = z.Read(testZoneNormalBuf)
			Expect(err).To(Succeed())
			err = dnsutils.AddDNSKEY(z, nsecSignOption, dnskeys, nil)
			Expect(err).To(Succeed())
			err = dnsutils.CreateDoE(z, nsecSignOption, nil)
			Expect(err).To(Succeed())
			err = dnsutils.SignZone(z, nsecSignOption, dnskeys, nil)
		})
		It("return success", func() {
			Expect(err).To(Succeed())
			Expect(dnsutils.IsEqualsAllTree(z.GetRootNode(), nsec_signed_zone.GetRootNode(), false)).To(BeTrue())
		})
	})
	Context("SignRRSet", func() {
		BeforeEach(func() {
			z = &dnsutils.Zone{}
			err = z.Read(bytes.NewBuffer(testSignZone))
			Expect(err).To(Succeed())
		})
		When("rrset type is not DNSKEY", func() {
			It("signs only with the ZSK", func() {
				aSet, aErr := dnsutils.NewRRSet("test.hoge.example.jp.", 3600, dns.ClassINET, dns.TypeA, nil)
				Expect(aErr).To(Succeed())
				Expect(aSet.AddRR(testtool.MustNewRR("test.hoge.example.jp. 3600 IN A 192.168.2.2"))).To(Succeed())

				rrsigs, sErr := dnsutils.SignRRSet(aSet, nsecSignOption, dnskeys)
				Expect(sErr).To(Succeed())
				Expect(rrsigs).To(HaveLen(1))
				Expect(rrsigs[0].KeyTag).To(Equal(zsk.GetRR().KeyTag()))
			})
		})
		When("rrset type is DNSKEY", func() {
			It("signs only with the KSK", func() {
				dnskeySet, dErr := dnsutils.NewRRSet("example.jp.", 3600, dns.ClassINET, dns.TypeDNSKEY, nil)
				Expect(dErr).To(Succeed())
				kskRR := dns.Copy(ksk.GetRR())
				kskRR.Header().Ttl = 3600
				zskRR := dns.Copy(zsk.GetRR())
				zskRR.Header().Ttl = 3600
				Expect(dnskeySet.AddRR(kskRR)).To(Succeed())
				Expect(dnskeySet.AddRR(zskRR)).To(Succeed())

				rrsigs, sErr := dnsutils.SignRRSet(dnskeySet, nsecSignOption, dnskeys)
				Expect(sErr).To(Succeed())
				Expect(rrsigs).To(HaveLen(1))
				Expect(rrsigs[0].KeyTag).To(Equal(ksk.GetRR().KeyTag()))
			})
		})
		When("the rrset has no records", func() {
			// SignRRSet does not guard against this: it hands the empty
			// slice straight to dns.RRSIG.Sign, which indexes rrset[0]
			// unconditionally and panics rather than returning an error.
			// Documented here as current behavior, not asserted as desired.
			It("panics instead of returning an error", func() {
				emptySet, eErr := dnsutils.NewRRSet("test.hoge.example.jp.", 3600, dns.ClassINET, dns.TypeA, nil)
				Expect(eErr).To(Succeed())

				Expect(func() {
					_, _ = dnsutils.SignRRSet(emptySet, nsecSignOption, dnskeys)
				}).To(Panic())
			})
		})
	})
	Context("SignNode", func() {
		var sub1Node dnsutils.NameNodeInterface
		BeforeEach(func() {
			z = &dnsutils.Zone{}
			err = z.Read(bytes.NewBuffer(testSignZone))
			Expect(err).To(Succeed())
			var ok bool
			sub1Node, ok = z.GetRootNode().GetNameNode("sub1.example.jp.")
			Expect(ok).To(BeTrue())
		})
		When("auth is false", func() {
			It("does not sign anything", func() {
				Expect(dnsutils.SignNode(sub1Node, nsecSignOption, dnskeys, nil, false, false)).To(Succeed())
				Expect(sub1Node.GetRRSet(dns.TypeRRSIG)).To(BeNil())
			})
		})
		When("auth is true but the node is not the zone apex (a delegation)", func() {
			It("signs DS but does not sign the NS rrset", func() {
				Expect(dnsutils.SignNode(sub1Node, nsecSignOption, dnskeys, nil, false, true)).To(Succeed())
				rrsigSet := sub1Node.GetRRSet(dns.TypeRRSIG)
				Expect(rrsigSet).NotTo(BeNil())
				var covered []uint16
				for _, rr := range rrsigSet.GetRRs() {
					covered = append(covered, rr.(*dns.RRSIG).TypeCovered)
				}
				Expect(covered).To(ConsistOf(dns.TypeDS))
			})
		})
		When("the node is the zone apex", func() {
			It("also signs the NS rrset", func() {
				rootNode := z.GetRootNode()
				Expect(dnsutils.SignNode(rootNode, nsecSignOption, dnskeys, nil, true, true)).To(Succeed())
				rrsigSet := rootNode.GetRRSet(dns.TypeRRSIG)
				Expect(rrsigSet).NotTo(BeNil())
				var covered []uint16
				for _, rr := range rrsigSet.GetRRs() {
					covered = append(covered, rr.(*dns.RRSIG).TypeCovered)
				}
				Expect(covered).To(ContainElement(dns.TypeNS))
			})
		})
	})
})
