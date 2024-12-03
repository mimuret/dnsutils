package dnsutils

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/miekg/dns"
)

var _ ZoneInterface = &Zone{}

// Zone is implement of ZoneInterface
type Zone struct {
	name      string
	root      NameNodeInterface
	class     dns.Class
	generator Generator
}

// NewZone creates Zone.
// returns ErrBadName when name is not domain name
func NewZone(name string, class dns.Class, generator Generator) (*Zone, error) {
	name = dns.CanonicalName(name)
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, ErrBadName
	}
	if generator == nil {
		generator = &DefaultGenerator{}
	}
	root, _ := generator.NewNameNode(name, class)
	return &Zone{
		name:      name,
		root:      root,
		class:     class,
		generator: generator,
	}, nil
}

// GetClass returns zone class
func (z *Zone) GetClass() dns.Class { return z.class }

// GetName returns canonical zone name
func (z *Zone) GetName() string { return z.name }

// GetRootNode returns zone apex NameNode
// If zone is not created by NewZone, maybe it returns nil
func (z *Zone) GetRootNode() NameNodeInterface { return z.root }

// GetGenerator returns Generator
func (z *Zone) GetGenerator() Generator { return z.generator }

// Read reads zone data from zonefile (RFC1035)
// It overrides zone's name and class when root node not exist.
func (z *Zone) Read(r io.Reader) error {
	zp := dns.NewZoneParser(r, z.GetName(), "")
	var (
		soa dns.RR
		rrs []dns.RR
	)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if rr.Header().Rrtype == dns.TypeSOA {
			soa = rr
		}
		rrs = append(rrs, rr)
	}
	if zp.Err() != nil {
		return fmt.Errorf("failed to parse zone data %w", zp.Err())
	}
	if soa == nil {
		return fmt.Errorf("not found SOA record")
	}
	if z.generator == nil {
		z.generator = &DefaultGenerator{}
	}
	if z.root == nil {
		z.class = dns.Class(soa.Header().Class)
		z.name = dns.CanonicalName(soa.Header().Name)
		z.root, _ = z.generator.NewNameNode(z.name, z.class)
	}
	for _, rr := range rrs {
		if !dns.IsSubDomain(z.GetName(), rr.Header().Name) {
			return fmt.Errorf("%s out of zone data", rr.Header().Name)
		}
		nn, ok := z.GetRootNode().GetNameNode(rr.Header().Name)
		if !ok || nn == nil {
			nn, _ = z.generator.NewNameNode(rr.Header().Name, z.GetClass())
		}
		set, _ := GetRRSetOrCreate(nn, rr.Header().Rrtype, rr.Header().Ttl, z.generator)
		if err := set.AddRR(rr); err != nil {
			return fmt.Errorf("failed to add RR %v: %w", set, err)
		}
		if err := nn.SetRRSet(set); err != nil {
			return fmt.Errorf("failed to set rrset: %w", err)
		}
		if err := SetNameNode(z.GetRootNode(), nn, z.generator); err != nil {
			return fmt.Errorf("failed to set node: %w", err)
		}
	}
	return ZoneNormalize(z)
}

func (z *Zone) Text(w io.Writer) {
	z.GetRootNode().IterateNameNode(func(nni NameNodeInterface) error {
		return nni.IterateNameRRSet(func(set RRSetInterface) error {
			for _, rr := range set.GetRRs() {
				w.Write([]byte(rr.String() + "\n"))
			}
			return nil
		})
	})
}

// UnmarshalJSON reads zone data from json.RawMessage.
// It override zone's name and class when root node not exist.
func (z *Zone) UnmarshalJSON(bs []byte) error {
	v := struct {
		Name   string  `json:"name"`
		Class  string  `json:"class"`
		RRSets []RRSet `json:"rrsets"`
	}{}
	if err := json.Unmarshal(bs, &v); err != nil {
		return fmt.Errorf("failed to parse json format: %w", err)
	}
	if _, ok := dns.IsDomainName(v.Name); !ok {
		return ErrBadName
	}
	if z.generator == nil {
		z.generator = &DefaultGenerator{}
	}
	if z.root == nil {
		z.name = dns.CanonicalName(v.Name)
		class, err := ConvertStringToClass(v.Class)
		if err != nil {
			return fmt.Errorf("invalid class %s", v.Class)
		}
		z.class = class
		z.root, _ = z.generator.NewNameNode(z.name, z.class)
	}

	for _, set := range v.RRSets {
		nn, ok := z.GetRootNode().GetNameNode(set.GetName())
		if !ok || nn == nil {
			nn, _ = z.generator.NewNameNode(set.GetName(), z.GetClass())
		}
		if err := nn.SetRRSet(&set); err != nil {
			return fmt.Errorf("failed to set rrset: %w", err)
		}
		if err := SetNameNode(z.GetRootNode(), nn, z.generator); err != nil {
			return fmt.Errorf("failed to set node: %w", err)
		}
	}

	return nil
}

// MarshalJSON returns json.RawMessage.
func (z *Zone) MarshalJSON() ([]byte, error) {
	v := struct {
		Name   string           `json:"name"`
		Class  string           `json:"class"`
		RRSets []RRSetInterface `json:"rrsets"`
	}{}
	v.Name = z.name
	v.Class = dns.ClassToString[uint16(z.GetClass())]
	z.GetRootNode().IterateNameNode(func(nni NameNodeInterface) error {
		return nni.IterateNameRRSet(func(set RRSetInterface) error {
			v.RRSets = append(v.RRSets, set.Copy())
			return nil
		})
	})
	return json.Marshal(v)
}

func ZoneNormalize(z ZoneInterface) error {
	if _, err := GetSOA(z); err != nil {
		return ErrBadZone
	}
	zoneCuts, delegateNS, err := GetZoneCuts(z.GetRootNode())
	if err != nil {
		return ErrBadZone
	}

	z.GetRootNode().IterateNameNode(func(nni NameNodeInterface) error {
		if IsENT(nni) {
			return nil
		}
		parent, strict := zoneCuts.GetNameNode(nni.GetName())
		if !strict && parent.GetName() != z.GetName() && parent.GetRRSet(dns.TypeNS) != nil {
			if _, ok := delegateNS[nni.GetName()]; !ok {
				RemoveNameNode(z.GetRootNode(), nni.GetName())
			}
		}
		return nil
	})

	return nil
}

func GetZoneCuts(rootNode NameNodeInterface) (NameNodeInterface, map[string]struct{}, error) {
	delegateNS := map[string]struct{}{}
	zoneCuts, _ := NewNameNode(rootNode.GetName(), rootNode.GetClass())
	err := rootNode.IterateNameNodeWithValue(func(nni NameNodeInterface, v any) (any, error) {
		aa := v.(bool)
		if !aa {
			return aa, nil
		}
		if nni.GetName() != rootNode.GetName() {
			if nsRRSet := nni.GetRRSet(dns.TypeNS); nsRRSet != nil {
				for _, rr := range nsRRSet.GetRRs() {
					if ns, ok := rr.(*dns.NS); ok {
						delegateNS[dns.CanonicalName(ns.Ns)] = struct{}{}
					} else {
						return aa, ErrInvalid
					}
				}
				zoneCut, _ := NewNameNode(nni.GetName(), rootNode.GetClass())
				zoneCut.SetRRSet(nsRRSet)
				zoneCuts.AddChildNameNode(zoneCut)
				aa = false
			}
		}
		return aa, nil
	}, true)
	if err != nil {
		return nil, nil, err
	}
	return zoneCuts, delegateNS, nil
}
