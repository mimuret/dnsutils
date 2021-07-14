package dnsutils

import (
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// name equal check.
// input name accept non-normalized name.
func Equals(a, b string) bool { return dns.CanonicalName(a) == dns.CanonicalName(b) }

// ENT check
func IsENT(n NameNodeInterface) bool {
	for _, set := range n.CopyRRSetMap() {
		if set.Len() > 0 {
			return false
		}
	}
	return true
}

// rrset equal check, ttl value will be ignored.
func IsEqualsRRSet(a, b RRSetInterface) bool {
	if a.GetName() != b.GetName() {
		return false
	}
	if a.GetRRtype() != b.GetRRtype() {
		return false
	}
	if a.Len() != b.Len() {
		return false
	}
	var arr, brr sort.StringSlice
	for _, rr := range a.GetRRs() {
		v := strings.SplitN(rr.String(), "\t", 5)
		arr = append(arr, v[4])
	}
	for _, rr := range b.GetRRs() {
		v := strings.SplitN(rr.String(), "\t", 5)
		brr = append(brr, v[4])
	}
	arr.Sort()
	brr.Sort()
	for i := range arr {
		if arr[i] != brr[i] {
			return false
		}
	}
	return true
}

// rrset equal check, ttl value not be ignored.
func IsCompleteEqualsRRSet(a, b RRSetInterface) bool {
	if IsEqualsRRSet(a, b) {
		if a.GetTTL() == b.GetTTL() {
			return true
		}
	}
	return false
}

// check empty rrset.
// if set is nil, it returns false.
// if set radata is empty, return false.
// other than that return true.
func IsEmptyRRSet(set RRSetInterface) bool {
	if set == nil {
		return true
	}
	return set.Len() == 0
}

// Get rrset.
// if exist rrset, returns it.
// if not exist rrset, It create new rrset and return it.
// but new rrset is not link to NameNode. Maybe you can use SetRRSet.
func GetRRSetOrCreate(n NameNodeInterface, rrtype uint16, ttl uint32) RRSetInterface {
	set := n.GetRRSet(rrtype)
	if set == nil {
		return NewRRSet(n.GetName(), ttl, n.GetClass(), rrtype, nil)
	}
	return set
}

// Get NameNode.
// if exist NameNode, returns it.
// if not exist NameNode, It create new NameNode and return it.
// but new NameNode is not link to arg NodeName. Maybe you can use SetNameNode.
func GetNameNodeOrCreate(n NameNodeInterface, name string) NameNodeInterface {
	nn, ok := n.GetNameNode(name)
	if !ok {
		nn = NewNameNode(name, n.GetClass())
	}
	return nn
}

// Get Rdata from dns.RR
func GetRDATA(rr dns.RR) string {
	v := strings.SplitN(rr.String(), "\t", 5)
	if len(v) != 5 {
		return ""
	}
	return v[4]
}

// Make dns.RR from RRSet, rdata string
func MakeRR(r RRSetInterface, rdata string) (dns.RR, error) {
	return dns.NewRR(r.GetName() + "\t" + strconv.FormatInt(int64(r.GetTTL()), 10) + "\t" + dns.ClassToString[uint16(r.GetClass())] + "\t" + dns.TypeToString[r.GetRRtype()] + "\t" + rdata)
}
