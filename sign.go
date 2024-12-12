package dnsutils

import (
	"crypto"
	"fmt"
	"io"
	"time"

	"github.com/miekg/dns"
)

type DenialOfExistenceMethod string

const (
	DenialOfExistenceMethodNSEC  = "NSEC"
	DenialOfExistenceMethodNSEC3 = "NSEC3"
)

var (
	DefaultBeforeSign time.Duration = time.Hour
	DefaultExpiry     time.Duration = time.Hour * 24 * 14
)

type SignOption struct {
	BeforeSign *time.Duration
	Expiry     *time.Duration
	Inception  *uint32
	Expiration *uint32
	// TODO: AddCDS     bool
	// TODO: AddCDNSKEY bool
	DoEMethod    DenialOfExistenceMethod
	NSEC3Salt    string
	NSEC3Iterate uint16

	ZONEMDEnabled bool
}

func (o *SignOption) GetBeforSign() time.Duration {
	if o.BeforeSign == nil {
		return DefaultBeforeSign
	}
	return *o.BeforeSign
}

func (o *SignOption) GetExpiry() time.Duration {
	if o.Expiry == nil {
		return DefaultExpiry
	}
	return *o.Expiry
}

func (o *SignOption) GetInception() uint32 {
	if o.Inception == nil {
		return uint32(time.Now().UTC().Add(-o.GetBeforSign()).Unix())
	}
	return *o.Inception
}

func (o *SignOption) GetExpiration() uint32 {
	if o.Expiration == nil {
		return uint32(time.Now().UTC().Add(o.GetExpiry()).Unix())
	}
	return *o.Expiration
}

func (o *SignOption) GetNSEC3Salt() string {
	return o.NSEC3Salt
}

func (o *SignOption) GetNSEC3Iterate() uint16 {
	return o.NSEC3Iterate
}

type DNSKEY struct {
	rr     *dns.DNSKEY
	signer crypto.Signer
}

func ReadDNSKEY(priv, pub io.Reader) (*DNSKEY, error) {
	var dnskey *dns.DNSKEY
	zp := dns.NewZoneParser(pub, "", "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if rr.Header().Rrtype == dns.TypeDNSKEY {
			dnskey, _ = rr.(*dns.DNSKEY)
		}
	}
	if dnskey == nil {
		return nil, fmt.Errorf("DNSKEY not found")
	}
	privateKey, err := dnskey.ReadPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("DNSKEY not found")
	}
	signer, _ := privateKey.(crypto.Signer)
	return &DNSKEY{
		rr:     dnskey,
		signer: signer,
	}, nil
}

func (d *DNSKEY) GetSigner() crypto.Signer {
	return d.signer
}

func (d *DNSKEY) GetRR() *dns.DNSKEY {
	return d.rr
}

func (d *DNSKEY) IsKSK() bool {
	return d.rr.Flags == 257
}

func (d *DNSKEY) IsZSK() bool {
	return d.rr.Flags == 256
}

func Sign(z ZoneInterface, opt SignOption, dnskeys []*DNSKEY, generator Generator) error {
	if err := AddDNSKEY(z, dnskeys, uint32(0), generator); err != nil {
		return fmt.Errorf("failed to add DNSKEY: %w", err)
	}
	if opt.ZONEMDEnabled {
		if err := AddZONEMDPlaceholder(z, nil, generator); err != nil {
			return fmt.Errorf("failed to add ZONEMD: %w", err)
		}
	}
	if err := CreateDoE(z, opt, generator); err != nil {
		return fmt.Errorf("failed to add NSEC or NSEC3: %w", err)
	}
	if err := SignZone(z, opt, dnskeys, generator); err != nil {
		return fmt.Errorf("failed to sign zone: %w", err)
	}
	if opt.ZONEMDEnabled {
		if err := UpdateZONEMDDigest(z, generator); err != nil {
			return fmt.Errorf("failed to update ZONEMD digest: %w", err)
		}
		if err := SignNode(z.GetRootNode(), opt, dnskeys, generator, true, true); err != nil {
			return fmt.Errorf("failed to sign zone apex: %w", err)
		}
	}
	return nil
}

func AddDNSKEY(z ZoneInterface, dnskeys []*DNSKEY, ttl uint32, generator Generator) error {
	if len(dnskeys) == 0 {
		return fmt.Errorf("empty DNSKEYs")
	}
	if ttl == 0 {
		ttl = 3600
	}
	rrset, err := GetRRSetOrCreate(z.GetRootNode(), dns.TypeDNSKEY, ttl, generator)
	if err != nil {
		return fmt.Errorf("failed to create DNSKEY rrset: %w", err)
	}
	for _, dnskey := range dnskeys {
		rr := dnskey.GetRR()
		rr.Hdr.Ttl = rrset.GetTTL()
		if err := rrset.AddRR(rr); err != nil {
			return fmt.Errorf("failed to add DNSKEY RR: %w", err)
		}
	}
	if err := z.GetRootNode().SetRRSet(rrset); err != nil {
		return fmt.Errorf("failed to set DNSKEY rrset: %w", err)
	}
	return nil
}

func SignZone(z ZoneInterface, opt SignOption, dnskeys []*DNSKEY, generator Generator) error {
	if generator == nil {
		generator = &DefaultGenerator{}
	}
	// Sign
	return z.GetRootNode().IterateNameNodeWithValue(func(nni NameNodeInterface, a any) (any, error) {
		auth := a.(bool)
		if z.GetName() != nni.GetName() {
			if nsRRset := nni.GetRRSet(dns.TypeNS); nsRRset != nil {
				return false, SignNode(nni, opt, dnskeys, generator, nni == z.GetRootNode(), true)
			}
		}
		return auth, SignNode(nni, opt, dnskeys, generator, nni == z.GetRootNode(), auth)
	}, true)
}

func SignNode(nni NameNodeInterface, opt SignOption, dnskeys []*DNSKEY, generator Generator, apex, auth bool) error {
	if generator == nil {
		generator = &DefaultGenerator{}
	}
	if !auth {
		return nil
	}
	rrsig, err := generator.NewRRSet(nni.GetName(), 0, nni.GetClass(), dns.TypeRRSIG)
	if err != nil {
		return err
	}
	err = nni.IterateNameRRSet(func(ri RRSetInterface) error {
		if ri.GetRRtype() == dns.TypeNS && !apex {
			return nil
		}
		if ri.GetRRtype() == dns.TypeRRSIG {
			return nil
		}
		rrsigRRs, err := SignRRSet(ri, opt, dnskeys)
		if err != nil {
			return err
		}
		for _, rr := range rrsigRRs {
			rrsig.AddRR(rr)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to sign rrset: %w", err)
	}
	if len(rrsig.GetRRs()) == 0 {
		return nil
	}
	return nni.SetRRSet(rrsig)
}

func SignRRSet(ri RRSetInterface, opt SignOption, dnskeys []*DNSKEY) ([]*dns.RRSIG, error) {
	var rrs []*dns.RRSIG
	for _, dnskey := range dnskeys {
		if (ri.GetRRtype() == dns.TypeDNSKEY && dnskey.IsKSK()) ||
			(ri.GetRRtype() != dns.TypeDNSKEY && dnskey.IsZSK()) {
			rrsig := &dns.RRSIG{
				Hdr: dns.RR_Header{
					Ttl: ri.GetTTL(),
				},
				KeyTag:     dnskey.GetRR().KeyTag(),
				SignerName: dnskey.GetRR().Header().Name,
				Algorithm:  dnskey.GetRR().Algorithm,
				Inception:  opt.GetInception(),
				Expiration: opt.GetExpiration(),
			}

			if err := rrsig.Sign(dnskey.GetSigner(), ri.GetRRs()); err != nil {
				return nil, fmt.Errorf("failed to sign: %w", err)
			}
			rrs = append(rrs, rrsig)
		}
	}
	return rrs, nil
}
