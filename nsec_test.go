package dnsutils_test

import (
	"bytes"
	_ "embed"

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
			DoEMethod:  dnsutils.DenialOfExistenceMethodNSEC,
			Inception:  &inception,
			Expiration: &expiration,
		}
		nsec3SignOption = dnsutils.SignOption{
			DoEMethod:  dnsutils.DenialOfExistenceMethodNSEC3,
			Inception:  &inception,
			Expiration: &expiration,
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
					err = dnsutils.AddDNSKEY(z, dnskeys, uint32(0), nil)
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
					err = dnsutils.AddDNSKEY(z, dnskeys, uint32(0), nil)
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
})
