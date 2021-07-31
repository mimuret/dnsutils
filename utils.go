package dnsutils

import (
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var (
	ErrRdata = dns.ErrRdata
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
func GetRRSetOrCreate(n NameNodeInterface, rrtype uint16, ttl uint32) (RRSetInterface, error) {
	set := n.GetRRSet(rrtype)
	if set == nil {
		return NewRRSet(n.GetName(), ttl, n.GetClass(), rrtype, nil)
	}
	return set, nil
}

// Get NameNode.
// if exist NameNode, returns it.
// if not exist NameNode, It create new NameNode and return it.
// but new NameNode is not link to arg NodeName. Maybe you can use SetNameNode.
func GetNameNodeOrCreate(n NameNodeInterface, name string) (NameNodeInterface, error) {
	name = dns.CanonicalName(name)
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, ErrBadName
	}
	if !dns.IsSubDomain(n.GetName(), name) {
		return nil, ErrNotSubdomain
	}
	nn, ok := n.GetNameNode(name)
	if !ok {
		return NewNameNode(name, n.GetClass())
	}
	return nn, nil
}

// Get Rdata from dns.RR
func GetRDATA(rr dns.RR) string {
	v := strings.SplitN(rr.String(), "\t", 5)
	if len(v) != 5 {
		return ""
	}
	return v[4]
}

// Get Rdata from dns.RR
func GetRDATASlice(rrset RRSetInterface) []string {
	rdata := []string{}
	rdataMap := map[string]struct{}{}
	for _, rr := range rrset.GetRRs() {
		s := GetRDATA(rr)
		if _, ok := rdataMap[s]; !ok {
			rdata = append(rdata, s)
		}
		rdataMap[s] = struct{}{}
	}
	return rdata
}

// set rdata into rrset
func SetRdata(set RRSetInterface, rdata []string) error {
	rrs := []dns.RR{}
	for _, v := range rdata {
		rr, err := MakeRR(set, v)
		if err != nil {
			return ErrRdata
		}
		rrs = append(rrs, rr)
	}
	for _, rr := range rrs {
		if err := set.AddRR(rr); err != nil {
			return err
		}
	}
	return nil

}

// Make dns.RR from RRSet, rdata string
func MakeRR(r RRSetInterface, rdata string) (dns.RR, error) {
	return dns.NewRR(r.GetName() + "\t" + strconv.FormatInt(int64(r.GetTTL()), 10) + "\t" + dns.ClassToString[uint16(r.GetClass())] + "\t" + dns.TypeToString[r.GetRRtype()] + "\t" + rdata)
}

func ConvertStringToType(s string) (uint16, error) {
	return convertStringToUint16(dns.StringToType, "TYPE", s)
}

func ConvertStringToClass(s string) (dns.Class, error) {
	class, err := convertStringToUint16(dns.StringToClass, "CLASS", s)
	return dns.Class(class), err
}

func convertStringToUint16(def map[string]uint16, prefix, s string) (uint16, error) {
	if t, ok := def[s]; ok {
		return t, nil
	}
	if strings.HasPrefix(s, prefix) {
		v := strings.TrimLeft(s, prefix)
		res, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return 0, ErrInvalid
		}
		return uint16(res), nil
	}
	return 0, ErrInvalid
}

func ConvertTypeToString(i uint16) string {
	return convertUint1ToString(dns.TypeToString, "TYPE", i)
}

func ConvertClassToString(i dns.Class) string {
	return convertUint1ToString(dns.ClassToString, "CLASS", uint16(i))
}

func convertUint1ToString(def map[uint16]string, prefix string, i uint16) string {
	if s, ok := def[i]; ok {
		return s
	}
	return prefix + strconv.FormatUint(uint64(i), 10)
}
