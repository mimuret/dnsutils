package dnsutils

import (
	"fmt"

	"github.com/miekg/dns"
)

var (
	ErrRRName   = fmt.Errorf("Not equals rr name")
	ErrRRType   = fmt.Errorf("Not equals rrtype")
	ErrConflict = fmt.Errorf("Conflict RR")
)

type RRSet struct {
	name   string
	rrtype uint16
	rrs    []dns.RR
}

func NewRRSet(name string, rrtype uint16, rrs []dns.RR) *RRSet {
	name = dns.CanonicalName(name)
	return &RRSet{
		name:   name,
		rrtype: rrtype,
		rrs:    rrs,
	}
}

func (r *RRSet) GetName() string {
	return r.name
}

// return rtype
func (r *RRSet) GetRRtype() uint16 {
	return r.rrtype
}

// return rr slice
func (r *RRSet) GetRRs() []dns.RR {
	return r.rrs
}

func (r *RRSet) AddRR(rr dns.RR) error {
	if !Equals(r.name, rr.Header().Name) {
		return ErrRRName
	}
	if rr.Header().Rrtype != r.rrtype {
		return ErrRRType
	}
	if len(r.rrs) >= 1 {
		if rr.Header().Rrtype == dns.TypeCNAME {
			return ErrConflict
		}
		if rr.Header().Rrtype == dns.TypeSOA {
			return ErrConflict
		}
	}
	for _, v := range r.rrs {
		if v.String() == rr.String() {
			return nil
		}
	}
	r.rrs = append(r.rrs, rr)
	return nil
}

func (r *RRSet) RemoveRR(rr dns.RR) error {
	res := []dns.RR{}
	for _, crr := range r.rrs {
		if crr.String() != rr.String() {
			res = append(res, crr)
		}
	}
	r.rrs = res
	return nil
}

func (r *RRSet) Len() int {
	return len(r.rrs)
}
