package testtool

import (
	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
)

type TestNameNodeInterface struct {
	NameNodeInterface dnsutils.NameNodeInterface
}

type TestGenerator struct {
	dnsutils.Generator
	NewNewNameNodeErr error
	NewRRSetErr       error
}

func (n *TestGenerator) NewNameNode(name string, class dns.Class) (dnsutils.NameNodeInterface, error) {
	if n.NewNewNameNodeErr != nil {
		return nil, n.NewNewNameNodeErr
	}
	return n.Generator.NewNameNode(name, dns.ClassCHAOS)
}
func (n *TestGenerator) NewRRSet(name string, ttl uint32, class dns.Class, rrtype uint16) (dnsutils.RRSetInterface, error) {
	if n.NewRRSetErr != nil {
		return nil, n.NewRRSetErr
	}
	return n.Generator.NewRRSet(name, ttl, class, rrtype)
}
