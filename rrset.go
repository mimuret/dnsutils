package dnsutils

import (
	"encoding/json"
	"fmt"

	"github.com/miekg/dns"
)

var _ RRSetInterface = &RRSet{}

var (
	// ErrTTL returns when rrset's ttl and rr's ttl are not equals.
	ErrTTLNotEqual = fmt.Errorf("not equals ttl")
	// ErrRRType returns when rrset's rrtype and rr's rrtype are not equals.
	ErrRRTypeNotEqual = fmt.Errorf("not equals rrtype")
	// ErrConflict returns when there is more than one SOA RDATA or CNAME RDATA.
	ErrConflict = fmt.Errorf("conflict RR")
	// ErrInvalid returns when class or type is invalid format.
	ErrInvalid = fmt.Errorf("invalid data")
	// ErrFormat returns when input invalid format data.
	ErrFormat = fmt.Errorf("input format error")
)

// RRSet is implement of RRSetInterface
type RRSet struct {
	name   string
	ttl    uint32
	rrtype uint16
	class  dns.Class
	rrs    []dns.RR
}

// NewRRSet creates RRSet.
// Returns ErrBadName when name is not domain name
func NewRRSet(name string, ttl uint32, class dns.Class, rrtype uint16, rrs []dns.RR) (*RRSet, error) {
	name = dns.CanonicalName(name)
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, ErrBadName
	}
	return &RRSet{
		name:   name,
		ttl:    ttl,
		rrtype: rrtype,
		class:  class,
		rrs:    rrs,
	}, nil
}

// NewRRSetFromRR creates RRSet from dns.RR
// If rr is nil return nil
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

// NewRRSetFromRRs creates RRSet from []dns.RR.
// It creates RRset by first RR using NewRRSetFromRR.
// 2nd and subsequent RR are add rrset using RRSet.AddRR.
// If RRSet.AddRR failed, return nil
// If rrs is nil return nil
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

// GetName returns canonical name
func (r *RRSet) GetName() string {
	return r.name
}

// GetTTL returns ttl
func (r *RRSet) GetTTL() uint32 {
	return r.ttl
}

// SetTTL changes RRSet.ttl.
// And changes all of RRSet rr ttl.
func (r *RRSet) SetTTL(ttl uint32) error {
	for _, rr := range r.rrs {
		rr.Header().Ttl = ttl
	}
	r.ttl = ttl
	return nil
}

// GetRRtype returns rtype
func (r *RRSet) GetRRtype() uint16 {
	return r.rrtype
}

// GetClass returns dns.Class
func (r *RRSet) GetClass() dns.Class {
	return r.class
}

// GetRRs returns []dns.RR
func (r *RRSet) GetRRs() []dns.RR {
	return r.rrs
}

// AddRR add resource record
// rr is must equals al of name,ttl,class and rrtype.
// if duplicate RDATA, It will be ignored.
// It returns err when any of name, ttl, class and rrtype not equal.
// It returns err when rtype is SOA or CNAME, and it number is multiple.
func (r *RRSet) AddRR(rr dns.RR) error {
	if !Equals(r.name, rr.Header().Name) {
		return ErrNameNotEqual
	}
	if rr.Header().Rrtype != r.rrtype {
		return ErrRRTypeNotEqual
	}
	if rr.Header().Rrtype != dns.TypeRRSIG && rr.Header().Ttl != r.ttl {
		return ErrTTLNotEqual
	}
	if rr.Header().Class != uint16(r.class) {
		return ErrClassNotEqual
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

// RemoveRR removes resource record
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

// Copy returns copy rrset
func (r *RRSet) Copy() RRSetInterface {
	copy := &RRSet{}
	*copy = *r
	return copy
}

// Len returns number of rdata
func (r *RRSet) Len() int {
	return len(r.rrs)
}

type jsonRRSetStruct struct {
	Name   string   `json:"name"`
	Class  string   `json:"class"`
	TTL    uint32   `json:"ttl"`
	RRtype string   `json:"rrtype"`
	RDATA  []string `json:"rdata"`
}

// UnmarshalJSON reads rrset data from json.RawMessage.
func (r *RRSet) UnmarshalJSON(bs []byte) error {
	var (
		v = &jsonRRSetStruct{}
	)
	if err := json.Unmarshal(bs, v); err != nil {
		return fmt.Errorf("failed to parse json format: %w", err)
	}
	r.name = dns.CanonicalName(v.Name)
	class, err := ConvertStringToClass(v.Class)
	if err != nil {
		return fmt.Errorf("invalid class %s", v.Class)
	}
	r.class = class
	r.ttl = uint32(v.TTL)
	rrtype, err := ConvertStringToType(v.RRtype)
	if err != nil {
		return fmt.Errorf("not support rrtype %s", v.RRtype)
	}
	r.rrtype = rrtype
	if len(v.RDATA) == 0 {
		return fmt.Errorf("rdata must not be empty")
	}
	if err := SetRdata(r, v.RDATA); err != nil {
		return fmt.Errorf("failed to set Rdata: %w", err)
	}
	return nil
}

// MarshalJSON returns json.RawMessage.
func (r *RRSet) MarshalJSON() ([]byte, error) {
	return MarshalJSONRRSet(r)
}

// MarshalJSONRRset returns json.RawMessage by rrset.
func MarshalJSONRRSet(set RRSetInterface) ([]byte, error) {
	v := &jsonRRSetStruct{}
	v.Name = set.GetName()
	v.Class = ConvertClassToString(set.GetClass())
	v.TTL = set.GetTTL()
	v.RRtype = ConvertTypeToString(set.GetRRtype())
	v.RDATA = GetRDATASlice(set)
	return json.Marshal(v)
}
