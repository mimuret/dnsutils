package dnsutils

import (
	"fmt"

	"github.com/miekg/dns"
)

var _ RRSetInterface = &RRSet{}

var (
	ErrTTL      = fmt.Errorf("Not equals ttl")
	ErrRRName   = fmt.Errorf("Not equals rr name")
	ErrRRType   = fmt.Errorf("Not equals rrtype")
	ErrClass    = fmt.Errorf("Not equals class")
	ErrConflict = fmt.Errorf("Conflict RR")
)

// RRSet
type RRSet struct {
	name   string
	ttl    uint32
	rrtype uint16
	class  dns.Class
	rrs    []dns.RR
}

// create RRSet. Not return nil
func NewRRSet(name string, ttl uint32, class dns.Class, rrtype uint16, rrs []dns.RR) *RRSet {
	name = dns.CanonicalName(name)
	return &RRSet{
		name:   name,
		ttl:    ttl,
		rrtype: rrtype,
		class:  class,
		rrs:    rrs,
	}
}

// create RRSet from rr
// if rr is nil return nil
func NewRRSetFromRR(rr dns.RR) *RRSet {
	if rr == nil {
		return nil
	}
	return &RRSet{
		name:   dns.CanonicalName(rr.Header().Name),
		ttl:    rr.Header().Ttl,
		rrtype: rr.Header().Rrtype,
		class:  dns.Class(rr.Header().Class),
		rrs:    []dns.RR{rr},
	}
}

// create RRSet from rrs.
// It creates by first RR useing NewRRSetFromRR.
// And add RR 2nd and subsequent RR.
// if AddRR failed, return nil
// if rrs is nil return nil
func NewRRSetFromRRs(rrs []dns.RR) *RRSet {
	if len(rrs) == 0 {
		return nil
	}
	var set *RRSet
	for _, rr := range rrs {
		if set == nil {
			set = NewRRSetFromRR(rr)
		} else {
			if err := set.AddRR(rr); err != nil {
				return nil
			}
		}
	}
	return set
}

// return canonical name
func (r *RRSet) GetName() string {
	return r.name
}

// return ttl
func (r *RRSet) GetTTL() uint32 {
	return r.ttl
}

// set ttl. It change RRs ttl too.
func (r *RRSet) SetTTL(ttl uint32) {
	for _, rr := range r.rrs {
		rr.Header().Ttl = ttl
	}
	r.ttl = ttl
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

// Add resource record
// rr is must equals al of name,ttl,class and rrtype.
// if duplicate RDATA, It will be ignored.
// It returns err when any of name, ttl, class and rrtype not equal.
// It returns err when rtype is SOA or CNAME, and it number is multiple.
func (r *RRSet) AddRR(rr dns.RR) error {
	if !Equals(r.name, rr.Header().Name) {
		return ErrRRName
	}
	if rr.Header().Rrtype != r.rrtype {
		return ErrRRType
	}
	if rr.Header().Ttl != r.ttl {
		return ErrTTL
	}
	if rr.Header().Class != uint16(r.class) {
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

// remove resource record
// if not match rr. It will be ignored.
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

// copy rrset
func (r *RRSet) Copy() RRSetInterface {
	copy := &RRSet{}
	*copy = *r
	return copy
}

// return number of rdata
func (r *RRSet) Len() int {
	return len(r.rrs)
}
