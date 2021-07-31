package dnsutils

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/miekg/dns"
)

var _ ZoneInterface = &Zone{}

type Zone struct {
	name  string
	root  NameNodeInterface
	class dns.Class
}

// create Zone. Not return nil
func NewZone(name string, class dns.Class) (*Zone, error) {
	name = dns.CanonicalName(name)
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, ErrBadName
	}
	root, _ := NewNameNode(name, class)
	return &Zone{
		name:  name,
		root:  root,
		class: class,
	}, nil
}

// return dns.Class
func (z *Zone) GetClass() dns.Class { return z.class }

// return canonical zone name
func (z *Zone) GetName() string { return z.name }

// return zone apex NameNode
func (z *Zone) GetRootNode() NameNodeInterface { return z.root }

// read zonefile format data
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
	z.class = dns.Class(soa.Header().Class)
	z.name = dns.CanonicalName(soa.Header().Name)
	if z.root == nil {
		z.root, _ = NewNameNode(z.name, z.class)
	}
	for _, rr := range rrs {
		nn, ok := z.GetRootNode().GetNameNode(rr.Header().Name)
		if !ok || nn == nil {
			nn, _ = NewNameNode(rr.Header().Name, z.GetClass())
		}
		set := GetRRSetOrCreate(nn, rr.Header().Rrtype, rr.Header().Ttl)
		if err := set.AddRR(rr); err != nil {
			return fmt.Errorf("failed to add RR %v: %w", set, err)
		}
		if err := nn.SetRRSet(set); err != nil {
			return fmt.Errorf("failed to set rrset: %w", err)
		}
		if err := z.GetRootNode().SetNameNode(nn); err != nil {
			return fmt.Errorf("failed to set node: %w", err)
		}
	}
	return nil
}

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
	z.name = dns.CanonicalName(v.Name)
	class, err := ConvertStringToClass(v.Class)
	if err != nil {
		return fmt.Errorf("invalid class %s", v.Class)
	}
	z.class = class

	if z.root == nil {
		z.root, _ = NewNameNode(z.name, z.class)
	}

	for _, set := range v.RRSets {
		nn, ok := z.GetRootNode().GetNameNode(set.GetName())
		if !ok || nn == nil {
			nn, _ = NewNameNode(set.GetName(), z.GetClass())
		}
		if err := nn.SetRRSet(&set); err != nil {
			return fmt.Errorf("failed to set rrset: %w", err)
		}
		if err := z.GetRootNode().SetNameNode(nn); err != nil {
			return fmt.Errorf("failed to set node: %w", err)
		}
	}

	return nil
}

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
