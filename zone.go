package dnsutils

import (
	"github.com/miekg/dns"
)

var _ ZoneInterface = &Zone{}

type Zone struct {
	name string
	root NameNodeInterface
}

func NewZone(name string) *Zone {
	name = dns.CanonicalName(name)
	return &Zone{
		name: name,
		root: NewNameNode(dns.CanonicalName(name)),
	}
}

func (z *Zone) GetName() string { return z.name }

func (z *Zone) GetRootNode() NameNodeInterface { return z.root }
