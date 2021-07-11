package dnsutils

import (
	"fmt"

	"github.com/miekg/dns"
)

var _ RRSetInterface = &RRSet{}

var (
	ErrRRName   = fmt.Errorf("Not equals rr name")
	ErrRRType   = fmt.Errorf("Not equals rrtype")
	ErrClass    = fmt.Errorf("Not equals class")
	ErrConflict = fmt.Errorf("Conflict RR")
)

type RRSet struct {
	name   string
	rrtype uint16
	class  dns.Class
	rrs    []dns.RR
}

func NewRRSet(name string, rrtype uint16, class dns.Class, rrs []dns.RR) *RRSet {
	name = dns.CanonicalName(name)
	return &RRSet{
		name:   name,
		rrtype: rrtype,
		class:  class,
		rrs:    rrs,
	}
}
func NewRRSetFromRR(rr dns.RR) *RRSet {
	return &RRSet{
		name:   dns.CanonicalName(rr.Header().Name),
		rrtype: rr.Header().Rrtype,
		class:  dns.Class(rr.Header().Class),
		rrs:    []dns.RR{rr},
	}
}

func (r *RRSet) GetName() string {
	return r.name
}

// return rtype
func (r *RRSet) GetRRtype() uint16 {
	return r.rrtype
}

// return dns.Class
func (r *RRSet) GetClass() dns.Class {
	return r.class
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
	if rr.Header().Class != uint16(r.class) {
		fmt.Printf("%d %d\n", rr.Header().Class, r.class)
		return ErrClass
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

func (r *RRSet) Copy() RRSetInterface {
	copy := &RRSet{}
	*copy = *r
	return copy
}

func (r *RRSet) Len() int {
	return len(r.rrs)
}
