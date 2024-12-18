package dnsutils_test

import (
	"bytes"
	_ "embed"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
	. "github.com/mimuret/dnsutils/testtool"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//go:embed testdata/zonemd/example.simple.no-zonemd
var testExampleNoZONEMDData []byte

//go:embed testdata/zonemd/example.simple.zone
var testExampleSimpleData []byte

//go:embed testdata/zonemd/example.complex.zone
var testExampleComplexData []byte

//go:embed testdata/zonemd/example.complex.valid-zone
var testExampleComplexValidData []byte

//go:embed testdata/zonemd/example.multiple-support.zone
var testMultipleSupportData []byte

//go:embed testdata/zonemd/example.multiple.zone
var testMultipleData []byte

//go:embed testdata/zonemd/example.normalize.zone
var testNormalizeData []byte

//go:embed testdata/zonemd/uri.arpa.zone
var uriArpaZone []byte

//go:embed testdata/zonemd/root.zone
var rootZone []byte

//go:embed testdata/zonemd/keys/Kexample.+015+49842.private
var testZONEMDDnskeyED25519KSKPriv []byte

//go:embed testdata/zonemd/keys/Kexample.+015+49842.key
var testZONEMDDnskeyED25519KSKPub []byte

//go:embed testdata/zonemd/keys/Kexample.+015+04770.private
var testZONEMDDnskeyED25519ZSKPriv []byte

//go:embed testdata/zonemd/keys/Kexample.+015+04770.key
var testZONEMDDnskeyED25519ZSKPub []byte

var _ = Describe("zonemd", func() {
	var (
		err error
		z   *dnsutils.Zone
		ok  bool
	)
	Context("AddZONEMDPlaceholder", func() {
		When("empty ZONMED", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(testExampleNoZONEMDData))
				Expect(err).To(Succeed(), "read zone")
				err = dnsutils.AddZONEMDPlaceholder(z, nil, nil)
			})
			It("succeed", func() {
				Expect(err).To(Succeed())
				rrset := z.GetRootNode().GetRRSet(dns.TypeZONEMD)
				Expect(rrset).NotTo(BeNil())
				Expect(rrset.GetRRs()).To(HaveLen(1))
				Expect(rrset.GetRRs()[0]).To(Equal(MustNewRR("example. 86400 IN ZONEMD 2018031900 1 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")))
			})
		})
		When("ZONMED exists", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(testExampleSimpleData))
				Expect(err).To(Succeed(), "read zone")
				err = dnsutils.AddZONEMDPlaceholder(z, nil, nil)
			})
			It("succeed", func() {
				Expect(err).To(Succeed())
				rrset := z.GetRootNode().GetRRSet(dns.TypeZONEMD)
				Expect(rrset).NotTo(BeNil())
				Expect(rrset.GetRRs()).To(HaveLen(1))
				Expect(rrset.GetRRs()[0]).To(Equal(MustNewRR("example. 86400 IN ZONEMD 2018031900 1 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")))
			})
		})
	})
	Context("UpdateZONEMDDigest", func() {
		When("simple", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(testExampleNoZONEMDData))
				Expect(err).To(Succeed(), "read zone")
				err = dnsutils.AddZONEMDPlaceholder(z, nil, nil)
				Expect(err).To(Succeed(), "AddZONEMDPlaceholder")
				err = dnsutils.UpdateZONEMDDigest(z, nil)
			})
			It("succeed", func() {
				Expect(err).To(Succeed())
				rrset := z.GetRootNode().GetRRSet(dns.TypeZONEMD)
				Expect(rrset).NotTo(BeNil())
				Expect(rrset.GetRRs()).To(HaveLen(1))
				Expect(rrset.GetRRs()[0]).To(Equal(MustNewRR("example. 86400 IN ZONEMD 2018031900 1 1 c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c")))
			})
		})
		When("complex", func() {
			When("outout zone", func() {
				BeforeEach(func() {
					z = &dnsutils.Zone{}
					err = z.Read(bytes.NewBuffer(testExampleComplexData))
				})
				It("failed to read zone", func() {
					Expect(err).To(HaveOccurred(), "read zone")
				})
			})
			When("valid zone", func() {
				BeforeEach(func() {
					z = &dnsutils.Zone{}
					err = z.Read(bytes.NewBuffer(testExampleComplexValidData))
					Expect(err).To(Succeed(), "read zone")
					err = dnsutils.AddZONEMDPlaceholder(z, nil, nil)
					Expect(err).To(Succeed(), "AddZONEMDPlaceholder")
					err = dnsutils.UpdateZONEMDDigest(z, nil)
				})
				It("succeed", func() {
					Expect(err).To(Succeed())
					rrset := z.GetRootNode().GetRRSet(dns.TypeZONEMD)
					Expect(rrset).NotTo(BeNil())
					Expect(rrset.GetRRs()).To(HaveLen(1))
					Expect(rrset.GetRRs()[0]).To(Equal(MustNewRR("example. 86400 IN ZONEMD 2018031900 1 1 a3b69bad980a3504e1cffcb0fd6397f93848071c93151f552ae2f6b1711d4bd2d8b39808226d7b9db71e34b72077f8fe")))
				})
			})
		})
		When("Multiple Digests", func() {
			When("valid zone", func() {
				BeforeEach(func() {
					z = &dnsutils.Zone{}
					err = z.Read(bytes.NewBuffer(testMultipleSupportData))
					Expect(err).To(Succeed(), "read zone")
					err = dnsutils.AddZONEMDPlaceholder(z, []*dns.ZONEMD{
						{Scheme: dns.ZoneMDSchemeSimple, Hash: dns.ZoneMDHashAlgSHA384},
						{Scheme: dns.ZoneMDSchemeSimple, Hash: dns.ZoneMDHashAlgSHA512},
					}, nil)
					Expect(err).To(Succeed(), "AddZONEMDPlaceholder")
					err = dnsutils.UpdateZONEMDDigest(z, nil)
				})
				It("succeed", func() {
					Expect(err).To(Succeed())
					rrset := z.GetRootNode().GetRRSet(dns.TypeZONEMD)
					Expect(rrset).NotTo(BeNil())
					Expect(rrset.GetRRs()).To(HaveLen(2))
					eq := map[int8]dns.RR{
						dns.ZoneMDHashAlgSHA384: MustNewRR("example. 86400 IN ZONEMD 2018031900 1 1 62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637493daaf401c92c279dd10f0edb1c56f8080211f8480ee306"),
						dns.ZoneMDHashAlgSHA512: MustNewRR("example. 86400 IN ZONEMD 2018031900 1 2 08cfa1115c7b948c4163a901270395ea226a930cd2cbcf2fa9a5e6eb85f37c8a4e114d884e66f176eab121cb02db7d652e0cc4827e7a3204f166b47e5613fd27"),
					}
					for _, rr := range rrset.GetRRs() {
						zonemd := rr.(*dns.ZONEMD)
						Expect(rr).To(Equal(eq[int8(zonemd.Hash)]))
					}
				})
			})
		})
	})
	Context("CalcZONEMD", func() {
		var (
			digest string
		)
		When("normalize zone", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(testNormalizeData))
				Expect(err).To(Succeed(), "read zone")
				zonemd := MustNewRR("example.	86400	IN	ZONEMD	2018031900 1 1 0").(*dns.ZONEMD)
				digest, err = dnsutils.CalcZONEMD(z, zonemd)
			})
			It("returns true", func() {
				Expect(err).To(Succeed())
				Expect(digest).To(Equal("f3ee6ced3a4af3dc0c82abef485311482218da9649af8b6c332c4fd2dd31a44a8e48f8b8e4717db08e244e0a26a020d7"))
			})
		})
		When("unkown schema", func() {
			BeforeEach(func() {
				zonemd := MustNewRR("example.	86400	IN	ZONEMD	2018031900 0 1 0").(*dns.ZONEMD)
				_, err = dnsutils.CalcZONEMD(nil, zonemd)
			})
			It("returns ErrZONEMDUnknownSchema", func() {
				Expect(err).To(Equal(dnsutils.ErrZONEMDUnknownSchema))
			})
		})
		When("unkown hash", func() {
			BeforeEach(func() {
				zonemd := MustNewRR("example.	86400	IN	ZONEMD	2018031900 1 0 0").(*dns.ZONEMD)
				_, err = dnsutils.CalcZONEMD(nil, zonemd)
			})
			It("returns ErrZONEMDUnknownSchema", func() {
				Expect(err).To(Equal(dnsutils.ErrZONEMDUnknownHash))
			})
		})
	})
	Context("VerifyZONEMDDigest", func() {
		When("valid ZONEMD", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(testExampleComplexValidData))
				Expect(err).To(Succeed(), "read zone")
				zonemd := MustNewRR("example.	86400	IN	ZONEMD	2018031900 1 1 a3b69bad980a3504e1cffcb0fd6397f93848071c93151f552ae2f6b1711d4bd2d8b39808226d7b9db71e34b72077f8fe").(*dns.ZONEMD)
				ok, err = dnsutils.VerifyZONEMDDigest(z, zonemd)
			})
			It("returns true", func() {
				Expect(err).To(Succeed())
				Expect(ok).To(BeTrue())
			})
		})
		When("invalid ZONEMD", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(testExampleComplexValidData))
				Expect(err).To(Succeed(), "read zone")
				zonemd := MustNewRR("example.	86400	IN	ZONEMD	2018031900 1 1 000").(*dns.ZONEMD)
				ok, err = dnsutils.VerifyZONEMDDigest(z, zonemd)
			})
			It("returns false", func() {
				Expect(err).To(Succeed())
				Expect(ok).To(BeFalse())
			})
		})
	})
	Context("VerifyAnyZONEMDDigest", func() {
		When("valid ZONEMD", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(testMultipleData))
				Expect(err).To(Succeed(), "read zone")
				ok, err = dnsutils.VerifyAnyZONEMDDigest(z)
			})
			It("returns true", func() {
				Expect(err).To(Succeed())
				Expect(ok).To(BeTrue())
			})
		})
		When("root zone", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(rootZone))
				Expect(err).To(Succeed(), "read zone")
				ok, err = dnsutils.VerifyAnyZONEMDDigest(z)
			})
			It("returns true", func() {
				Expect(err).To(Succeed())
				Expect(ok).To(BeTrue())
			})
		})
		When("uri.arpa zone", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(uriArpaZone))
				Expect(err).To(Succeed(), "read zone")
				ok, err = dnsutils.VerifyAnyZONEMDDigest(z)
			})
			It("returns true", func() {
				Expect(err).To(Succeed())
				Expect(ok).To(BeTrue())
			})
		})
		When("uri.arpa zone", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(uriArpaZone))
				Expect(err).To(Succeed(), "read zone")
				ok, err = dnsutils.VerifyAnyZONEMDDigest(z)
			})
			It("returns true", func() {
				Expect(err).To(Succeed())
				Expect(ok).To(BeTrue())
			})
		})
		When("apex zonemd doesn't exist", func() {
			BeforeEach(func() {
				z = &dnsutils.Zone{}
				err = z.Read(bytes.NewBuffer(testExampleNoZONEMDData))
				Expect(err).To(Succeed(), "read zone")
				ok, err = dnsutils.VerifyAnyZONEMDDigest(z)
			})
			It("returns true", func() {
				Expect(err).To(Equal(dnsutils.ErrZONEMDVerifySkip))
			})
		})
	})
	Context("UpdateZONEMDDigest & Sign", func() {
		var (
			inception      = uint32(1704067200)
			expiration     = uint32(1893456000)
			nsecSignOption = dnsutils.SignOption{
				DoEMethod:      dnsutils.DenialOfExistenceMethodNSEC,
				Inception:      &inception,
				Expiration:     &expiration,
				ZONEMDEnabled:  &True,
				CDSEnabled:     &False,
				CDNSKEYEnabled: &False,
			}
			nsec3SignOption = dnsutils.SignOption{
				DoEMethod:      dnsutils.DenialOfExistenceMethodNSEC3,
				Inception:      &inception,
				Expiration:     &expiration,
				ZONEMDEnabled:  &True,
				CDSEnabled:     &False,
				CDNSKEYEnabled: &False,
			}
			zsk     *dnsutils.DNSKEY
			ksk     *dnsutils.DNSKEY
			dnskeys []*dnsutils.DNSKEY
		)
		BeforeEach(func() {
			ksk, err = dnsutils.ReadDNSKEY(bytes.NewBuffer(testZONEMDDnskeyED25519KSKPriv), bytes.NewBuffer(testZONEMDDnskeyED25519KSKPub))
			Expect(err).To(Succeed())
			zsk, err = dnsutils.ReadDNSKEY(bytes.NewBuffer(testZONEMDDnskeyED25519ZSKPriv), bytes.NewBuffer(testZONEMDDnskeyED25519ZSKPub))
			Expect(err).To(Succeed())
			dnskeys = []*dnsutils.DNSKEY{ksk, zsk}
			z = &dnsutils.Zone{}
			err = z.Read(bytes.NewBuffer(testExampleComplexValidData))
		})
		Context("sign with nsec", func() {
			BeforeEach(func() {
				err = dnsutils.Sign(z, nsecSignOption, dnskeys, nil)
				Expect(err).To(Succeed())
				ok, err = dnsutils.VerifyAnyZONEMDDigest(z)
			})
			It("returns true", func() {
				Expect(err).To(Succeed())
				Expect(ok).To(BeTrue())
			})
		})
		Context("sign with nsec3", func() {
			BeforeEach(func() {
				err = dnsutils.Sign(z, nsec3SignOption, dnskeys, nil)
				Expect(err).To(Succeed())
				ok, err = dnsutils.VerifyAnyZONEMDDigest(z)
			})
			It("returns true", func() {
				Expect(err).To(Succeed())
				Expect(ok).To(BeTrue())
			})
		})
	})
})
