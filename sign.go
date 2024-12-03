package dnsutils

import (
	"crypto"
	"fmt"
	"io"
	"sort"
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
	DoEMethod  DenialOfExistenceMethod
	BeforeSign *time.Duration
	Expiry     *time.Duration
	Inception  *uint32
	Expiration *uint32
	// TODO: AddCDS     bool
	// TODO: AddCDNSKEY bool
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
				return false, signNode(nni, opt, dnskeys, generator, nni == z.GetRootNode(), true)
			}
		}
		return auth, signNode(nni, opt, dnskeys, generator, nni == z.GetRootNode(), auth)
	}, true)
}

func signNode(nni NameNodeInterface, opt SignOption, dnskeys []*DNSKEY, generator Generator, apex, auth bool) error {
	if !auth {
		return nil
	}
	rrsig, err := GetRRSetOrCreate(nni, dns.TypeRRSIG, 0, generator)
	if err != nil {
		return err
	}
	err = nni.IterateNameRRSet(func(ri RRSetInterface) error {
		if ri.GetRRtype() == dns.TypeNS && !apex {
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

func CreateDoE(z ZoneInterface, opt SignOption, generator RRSetGenerator) error {
	if generator == nil {
		generator = &DefaultGenerator{}
	}
	switch opt.DoEMethod {
	case DenialOfExistenceMethodNSEC, "":
		return createNSEC(z, generator)
	}
	return fmt.Errorf("not support: %s", opt.DoEMethod)
}

func createNSEC(z ZoneInterface, generator RRSetGenerator) error {
	var nodes = map[string]NameNodeInterface{}
	var names []string
	soa, err := GetSOA(z)
	if err != nil {
		return ErrBadZone
	}

	zoneCuts, _, err := GetZoneCuts(z.GetRootNode())
	if err != nil {
		return ErrBadZone
	}

	// get next domain names
	z.GetRootNode().IterateNameNode(func(nni NameNodeInterface) error {
		// Blocks with no types present MUST NOT be included
		if nni.RRSetLen() == 0 {
			return nil
		}
		// A zone MUST NOT include an NSEC RR for any domain name that only holds glue records
		parent, strict := zoneCuts.GetNameNode(nni.GetName())
		if parent.GetName() != z.GetName() {
			if !strict && parent.GetRRSet(dns.TypeNS) != nil {
				return nil
			}
		}
		nodes[nni.GetName()] = nni
		names = append(names, nni.GetName())
		return nil
	})

	sortedNames, _ := SortNames(names)
	for i, name := range sortedNames {
		nsec := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				// The NSEC RR SHOULD have the same TTL value as the SOA minimum TTL field.
				// This is in the spirit of negative caching ([RFC2308]).
				Ttl: soa.Minttl,
			},
			TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC},
		}
		if i+1 < len(sortedNames) {
			nsec.NextDomain = sortedNames[i+1]
		} else {
			nsec.NextDomain = sortedNames[0]
		}
		rresetMap := nodes[name].CopyRRSetMap()
		for rtype := range rresetMap {
			switch rtype {
			case dns.TypeRRSIG:
			case dns.TypeNSEC:
			default:
				nsec.TypeBitMap = append(nsec.TypeBitMap, rtype)
			}
		}
		sort.SliceStable(nsec.TypeBitMap, func(i, j int) bool { return nsec.TypeBitMap[i] < nsec.TypeBitMap[j] })

		set, err := generator.NewRRSet(name, soa.Minttl, dns.ClassINET, dns.TypeNSEC)
		if err != nil {
			return err
		}
		if err := set.AddRR(nsec); err != nil {
			return err
		}
		if err := nodes[name].SetRRSet(set); err != nil {
			return err
		}
	}
	return nil
}
