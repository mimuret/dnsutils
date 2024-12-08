package dnsutils

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

func CreateDoE(z ZoneInterface, opt SignOption, generator Generator) error {
	if generator == nil {
		generator = &DefaultGenerator{}
	}
	switch opt.DoEMethod {
	case DenialOfExistenceMethodNSEC, "":
		return createNSEC(z, generator)
	case DenialOfExistenceMethodNSEC3:
		return createNSEC3(z, opt, generator)
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

	SortNames(names)
	for i, name := range names {
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
		if i+1 < len(names) {
			nsec.NextDomain = names[i+1]
		} else {
			nsec.NextDomain = names[0]
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

var (
	ErrCollision = fmt.Errorf("hash collision detected")
)

func createNSEC3(z ZoneInterface, opt SignOption, generator Generator) error {
	var nodes = map[string]NameNodeInterface{}
	var hashCheckName = map[string]struct{}{}
	var names []string
	soa, err := GetSOA(z)
	if err != nil {
		return ErrBadZone
	}

	zoneCuts, _, err := GetZoneCuts(z.GetRootNode())
	if err != nil {
		return ErrBadZone
	}
	nsec3param := &dns.NSEC3PARAM{
		Hdr: dns.RR_Header{
			Name:   soa.Hdr.Name,
			Rrtype: dns.TypeNSEC3PARAM,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Hash:       dns.SHA1,
		Iterations: opt.GetNSEC3Iterate(),
		Salt:       opt.GetNSEC3Salt(),
	}

	nsec3ParamRRRet, err := NewRRSetFromRRWithGenerator(nsec3param, generator)
	if err != nil {
		return fmt.Errorf("failed to create nsec3param")
	}
	if err := z.GetRootNode().SetRRSet(nsec3ParamRRRet); err != nil {
		return fmt.Errorf("failed to set nsec3param")
	}

	// get next domain names
	err = z.GetRootNode().IterateNameNode(func(nni NameNodeInterface) error {
		parent, static := zoneCuts.GetNameNode(nni.GetName())
		if parent.GetName() != z.GetName() {
			if !static && parent.GetRRSet(dns.TypeNS) != nil {
				return nil
			}
		}
		nodes[nni.GetName()] = nni
		names = append(names, nni.GetName())

		hashCheckName[nni.GetName()] = struct{}{}
		labels := dns.SplitDomainName(nni.GetName())
		if len(labels) > 0 && labels[0] != "*" {
			hashCheckName["*."+nni.GetName()] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create name list: %w", err)
	}

	// collision check and make hash owner name
	hashMap := map[string]string{}
	hashCheck := map[string]string{}
	for name := range hashCheckName {
		hashName := dns.HashName(name, dns.SHA1, opt.GetNSEC3Iterate(), opt.GetNSEC3Salt())
		hashMap[name] = hashName
		if _, exist := hashCheck[hashName]; exist {
			return errors.Join(ErrCollision, fmt.Errorf("collision %s %s", hashCheck[hashName], name))
		} else {
			hashCheck[hashName] = name
		}
	}
	sort.Slice(names, func(i, j int) bool {
		cmp, _ := CompareName(hashMap[names[i]], hashMap[names[j]])
		return cmp < 0
	})
	for i, name := range names {
		nsec3 := &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   dns.CanonicalName(hashMap[name] + "." + z.GetName()),
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
				// The NSEC RR SHOULD have the same TTL value as the SOA minimum TTL field.
				// This is in the spirit of negative caching ([RFC2308]).
				Ttl: soa.Minttl,
			},
			Hash:       dns.SHA1,
			Iterations: opt.GetNSEC3Iterate(),
			Salt:       opt.GetNSEC3Salt(),
			SaltLength: uint8(len(opt.GetNSEC3Salt()) / 2),
			HashLength: 20, // SHA-1
		}
		if i+1 < len(names) {
			nsec3.NextDomain = strings.ToLower(hashMap[names[i+1]])
		} else {
			nsec3.NextDomain = strings.ToLower(hashMap[names[0]])
		}
		rresetMap := nodes[name].CopyRRSetMap()
		var (
			isZoneCust, haveDS bool
		)
		for rtype := range rresetMap {
			switch rtype {
			case dns.TypeRRSIG:
			case dns.TypeNSEC:
			case dns.TypeDS:
				nsec3.TypeBitMap = append(nsec3.TypeBitMap, rtype)
				haveDS = true
			case dns.TypeNS:
				nsec3.TypeBitMap = append(nsec3.TypeBitMap, rtype)
				if z.GetName() != name {
					isZoneCust = true
				}
			default:
				nsec3.TypeBitMap = append(nsec3.TypeBitMap, rtype)
			}
		}
		if !IsENT(nodes[name]) && (!isZoneCust || isZoneCust && haveDS) {
			nsec3.TypeBitMap = append(nsec3.TypeBitMap, dns.TypeRRSIG)
		}

		sort.SliceStable(nsec3.TypeBitMap, func(i, j int) bool { return nsec3.TypeBitMap[i] < nsec3.TypeBitMap[j] })

		if err := CreateOrReplaceRRSetFromRRs(z.GetRootNode(), []dns.RR{nsec3}, generator); err != nil {
			return fmt.Errorf("failed to create NSEC3 %s cover %s : %w", nsec3.Header().Name, name, err)
		}
	}
	return nil
}
