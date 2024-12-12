package dnsutils

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"math"
	"strings"

	"github.com/miekg/dns"
)

var (
	ErrZONEMDUnknownSchema = fmt.Errorf("unknown ZONEMD schema")
	ErrZONEMDUnknownHash   = fmt.Errorf("unknown ZONEMD hash")
	ErrZONEMDVerifySkip    = fmt.Errorf("skip ZONEMD verify")
)

var hashEmpty = map[uint8]string{
	dns.ZoneMDHashAlgSHA384: strings.Repeat("00", 48),
	dns.ZoneMDHashAlgSHA512: strings.Repeat("00", 64),
}

func removeRRSIG(nni NameNodeInterface, rrtype uint16) error {
	rrset := nni.GetRRSet(dns.TypeRRSIG)
	if rrset == nil {
		return nil
	}
	changed := false
	for _, rr := range rrset.GetRRs() {
		if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == rrtype {
			if err := rrset.RemoveRR(rr); err != nil {
				return fmt.Errorf("failed to remove cover RRSIG: %w", err)
			}
			changed = true
		}
	}
	if changed {
		return nni.SetRRSet(rrset)
	}
	return nil
}

// Add a ZONEMD placeholder.
// If there is already a ZONEMD record, delete it.
func AddZONEMDPlaceholder(z ZoneInterface, zonemdRRs []*dns.ZONEMD, generator RRSetGenerator) error {
	if generator == nil {
		generator = &DefaultGenerator{}
	}
	soa, err := GetSOA(z)
	if err != nil {
		return fmt.Errorf("invalid zone data: %w", err)
	}
	if len(zonemdRRs) == 0 {
		zonemdRRs = append(zonemdRRs, &dns.ZONEMD{
			Hdr: dns.RR_Header{
				Name:   z.GetName(),
				Rrtype: dns.TypeZONEMD,
				Class:  uint16(z.GetClass()),
				Ttl:    soa.Hdr.Ttl,
			},
			Serial: soa.Serial,
			Scheme: dns.ZoneMDSchemeSimple,
			Hash:   dns.ZoneMDHashAlgSHA384,
			Digest: hashEmpty[dns.ZoneMDHashAlgSHA384],
		})
	}
	var rrs []dns.RR
	for i := range zonemdRRs {
		zonemdRRs[i].Hdr.Name = z.GetName()
		zonemdRRs[i].Hdr.Rrtype = dns.TypeZONEMD
		zonemdRRs[i].Hdr.Class = uint16(z.GetClass())
		zonemdRRs[i].Hdr.Ttl = soa.Hdr.Ttl
		zonemdRRs[i].Serial = soa.Serial
		zonemdRRs[i].Digest = hashEmpty[zonemdRRs[i].Hash]
		rrs = append(rrs, zonemdRRs[i])
	}

	//3.1 In preparation for calculating the zone digest(s), any existing ZONEMD records
	// (and covering RRSIGs) at the zone apex are first deleted.
	if err := removeRRSIG(z.GetRootNode(), dns.TypeZONEMD); err != nil {
		return err
	}

	// add placeholder records
	rrset, err := NewRRSetFromRRsWithGenerator(rrs, generator)
	if err != nil {
		return fmt.Errorf("failed to create ZONEMD rrset: %w", err)
	}
	return z.GetRootNode().SetRRSet(rrset)
}

func UpdateZONEMDDigest(z ZoneInterface, generator RRSetGenerator) error {
	zonemdRRSet := z.GetRootNode().GetRRSet(dns.TypeZONEMD)
	if zonemdRRSet == nil {
		return nil
	}
	if len(zonemdRRSet.GetRRs()) == 0 {
		return nil
	}
	var err error
	var rrs []dns.RR
	for _, rr := range zonemdRRSet.GetRRs() {
		if zonemd, ok := rr.(*dns.ZONEMD); ok {
			digest, err := CalcZONEMD(z, zonemd)
			if err != nil {
				return fmt.Errorf("failed to calc ZONEMD digest: %w", err)
			}
			zonemd.Digest = digest
			rrs = append(rrs, zonemd)
		}
	}

	// add placeholder records
	rrset, err := NewRRSetFromRRsWithGenerator(rrs, generator)
	if err != nil {
		return fmt.Errorf("failed to create ZONEMD rrset: %w", err)
	}
	return z.GetRootNode().SetRRSet(rrset)
}

// Verifies the ZONEMD digst.
// If verification succeeds, return true
func VerifyZONEMDDigest(z ZoneInterface, zonemd *dns.ZONEMD) (bool, error) {
	digest, err := CalcZONEMD(z, zonemd)
	if err != nil {
		return false, err
	}
	return digest == zonemd.Digest, nil
}

// Verifies the ZONEMD digst.
// If apex ZONEMD does not exist, return false and ErrZONEMDVerifySkip.
// If verification succeeds, return true and nil.
func VerifyAnyZONEMDDigest(z ZoneInterface) (bool, error) {
	zonemdset := z.GetRootNode().GetRRSet(dns.TypeZONEMD)
	if zonemdset == nil {
		return false, ErrZONEMDVerifySkip
	}
	if len(zonemdset.GetRRs()) == 0 {
		return false, ErrZONEMDVerifySkip
	}
	for _, rr := range zonemdset.GetRRs() {
		zonemd, ok := rr.(*dns.ZONEMD)
		if !ok {
			continue
		}
		digest, err := CalcZONEMD(z, zonemd)
		if err != nil {
			continue
		}
		if digest == zonemd.Digest {
			return true, nil
		}
	}

	return false, nil
}

// Calculate ZONEMD digst.
func CalcZONEMD(z ZoneInterface, zonemd *dns.ZONEMD) (string, error) {
	switch zonemd.Scheme {
	case dns.ZoneMDSchemeSimple:
		return calcZONEMDSimple(z, zonemd)
	default:
		return "", ErrZONEMDUnknownSchema
	}
}

func calcZONEMDSimple(z ZoneInterface, zonemd *dns.ZONEMD) (string, error) {
	var rrs []dns.RR
	var hasher hash.Hash

	switch zonemd.Hash {
	case dns.ZoneMDHashAlgSHA384:
		hasher = sha512.New384()
	case dns.ZoneMDHashAlgSHA512:
		hasher = sha512.New()
	default:
		return "", ErrZONEMDUnknownHash
	}
	err := SortedIterateNameNode(z.GetRootNode(), func(nni NameNodeInterface) error {
		return SortedIterateRRset(nni, func(set RRSetInterface) error {
			if IsENT(nni) {
				return nil
			}
			if nni.GetName() == z.GetName() && set.GetRRtype() == dns.TypeZONEMD {
				// * The placeholder apex ZONEMD RR(s) MUST NOT be included.
				return nil
			}
			return SortedIterateRR(set, func(rr dns.RR) error {
				if nni.GetName() == z.GetName() && set.GetRRtype() == dns.TypeRRSIG {
					rrsig, ok := rr.(*dns.RRSIG)
					if !ok {
						return fmt.Errorf("failed to cast RRSIG")
					}
					if rrsig.TypeCovered == dns.TypeZONEMD {
						return nil
					}
				}
				rrs = append(rrs, rr)
				return nil
			})
		})
	})
	if err != nil {
		return "", fmt.Errorf("failed to create RRs: %w", err)
	}
	hashdata, err := hashRR(rrs, hasher)
	if err != nil {
		return "", fmt.Errorf("failed to create hash data: %w", err)
	}
	return hex.EncodeToString(hashdata), nil
}

func hashRR(rrs []dns.RR, hasher hash.Hash) ([]byte, error) {
	for _, r := range rrs {
		rr := dns.Copy(r)
		/*
			3. if the type of the RR is NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR, HINFO, MINFO,
			MX, HINFO, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX, SRV, DNAME, A6, RRSIG, or NSEC,
			all uppercase US-ASCII letters in the DNS names contained within the RDATA are
			replaced by the corresponding lowercase US-ASCII letters;
		*/
		switch x := rr.(type) {
		case *dns.NS:
			x.Ns = dns.CanonicalName(x.Ns)
		case *dns.MD:
			x.Md = dns.CanonicalName(x.Md)
		case *dns.MF:
			x.Mf = dns.CanonicalName(x.Mf)
		case *dns.CNAME:
			x.Target = dns.CanonicalName(x.Target)
		case *dns.SOA:
			x.Ns = dns.CanonicalName(x.Ns)
			x.Mbox = dns.CanonicalName(x.Mbox)
		case *dns.MB:
			x.Mb = dns.CanonicalName(x.Mb)
		case *dns.MG:
			x.Mg = dns.CanonicalName(x.Mg)
		case *dns.MR:
			x.Mr = dns.CanonicalName(x.Mr)
		case *dns.PTR:
			x.Ptr = dns.CanonicalName(x.Ptr)
			//		case *dns.HINFO:
			//	5.1.  Errors in Canonical Form Type Code List
		case *dns.MINFO:
			x.Rmail = dns.CanonicalName(x.Rmail)
			x.Email = dns.CanonicalName(x.Email)
		case *dns.MX:
			x.Mx = dns.CanonicalName(x.Mx)
		case *dns.RP:
			x.Mbox = dns.CanonicalName(x.Mbox)
			x.Txt = dns.CanonicalName(x.Txt)
		case *dns.AFSDB:
			x.Hostname = dns.CanonicalName(x.Hostname)
		case *dns.RT:
			x.Host = dns.CanonicalName(x.Host)
		case *dns.SIG:
			x.SignerName = dns.CanonicalName(x.SignerName)
		case *dns.PX:
			x.Map822 = dns.CanonicalName(x.Map822)
			x.Mapx400 = dns.CanonicalName(x.Mapx400)
			//		case *dns.NXT:
			// obsolute
		case *dns.NAPTR:
			x.Replacement = dns.CanonicalName(x.Replacement)
		case *dns.KX:
			x.Exchanger = dns.CanonicalName(x.Exchanger)
		case *dns.SRV:
			x.Target = dns.CanonicalName(x.Target)
		case *dns.DNAME:
			x.Target = dns.CanonicalName(x.Target)
			//		case *dns.A6
			// obsolute
		case *dns.RRSIG:
			x.SignerName = dns.CanonicalName(x.SignerName)
		case *dns.NSEC:
			x.NextDomain = dns.CanonicalName(x.NextDomain)
		case *dns.NSEC3:
			x.NextDomain = strings.ToLower(x.NextDomain)
		}
		buf := make([]byte, math.MaxUint16)
		off, err := dns.PackRR(rr, buf, 0, nil, false)
		if err != nil {
			return nil, fmt.Errorf("failed to pack RR %s: %w", rr.String(), err)
		}
		hasher.Write(buf[:off])
	}
	return hasher.Sum(nil), nil
}
