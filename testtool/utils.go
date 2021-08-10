package testtool

import (
	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
)

// USE ONLY TEST PACKAGE
func MustNewRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

func MustNewRRSet(name string, ttl uint32, class dns.Class, rrtype uint16, rrs []dns.RR) *dnsutils.RRSet {
	set, err := dnsutils.NewRRSet(name, ttl, class, rrtype, rrs)
	if err != nil {
		panic(err)
	}
	return set
}

func MustNewNameNode(name string, class dns.Class) *dnsutils.NameNode {
	nn, err := dnsutils.NewNameNode(name, class)
	if err != nil {
		panic(err)
	}
	return nn
}

func MustNewZone(name string, class dns.Class) *dnsutils.Zone {
	zone, err := dnsutils.NewZone(name, class, nil)
	if err != nil {
		panic(err)
	}
	return zone
}
