package dnsutils

import (
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func Equals(a, b string) bool { return dns.CanonicalName(a) == dns.CanonicalName(b) }

func IsENT(n NameNodeInterface) bool {
	for _, set := range n.CopyRRSetMap() {
		if set.Len() > 0 {
			return false
		}
	}
	return true
}

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
	arr := a.GetRRs()
	brr := b.GetRRs()
	sort.Slice(arr, func(i, j int) bool {
		return strings.Compare(arr[i].String(), arr[j].String()) > 0
	})
	sort.Slice(brr, func(i, j int) bool {
		return strings.Compare(brr[i].String(), brr[j].String()) > 0
	})
	for i := range arr {
		if arr[i].String() != brr[i].String() {
			return false
		}
	}
	return true
}

func IsEmptyRRSet(set RRSetInterface) bool {
	if set == nil {
		return true
	}
	return set.Len() == 0
}

func GetRRSetOrCreate(n NameNodeInterface, rrtype uint16, ttl uint32) RRSetInterface {
	set := n.GetRRSet(rrtype)
	if set == nil {
		return NewRRSet(n.GetName(), ttl, n.GetClass(), rrtype, nil)
	}
	return set
}

func GetRDATA(rr dns.RR) string {
	v := strings.SplitN(rr.String(), "\t", 5)
	if len(v) != 5 {
		return "<nil>"
	}
	return v[4]
}

func MakeRR(r RRSetInterface, rdata string) (dns.RR, error) {
	return dns.NewRR(r.GetName() + "\t" + strconv.FormatInt(int64(r.GetTTL()), 10) + "\t" + dns.ClassToString[uint16(r.GetClass())] + "\t" + dns.TypeToString[r.GetRRtype()] + "\t" + rdata)
}
