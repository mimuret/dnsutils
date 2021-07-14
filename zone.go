package dnsutils

import (
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
func NewZone(name string, class dns.Class) *Zone {
	name = dns.CanonicalName(name)
	return &Zone{
		name:  name,
		root:  NewNameNode(dns.CanonicalName(name), class),
		class: class,
	}
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
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		nn, ok := z.GetRootNode().GetNameNode(rr.Header().Name)
		if !ok || nn == nil {
			nn = NewNameNode(rr.Header().Name, z.GetClass())
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
	if zp.Err() != nil {
		return fmt.Errorf("failed to parse zone data %w", zp.Err())
	}
	return nil
}
