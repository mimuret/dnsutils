package dnsutils

import "github.com/miekg/dns"

func Equals(a, b string) bool { return dns.CanonicalName(a) == dns.CanonicalName(b) }

func IsENT(n NameNodeInterface) bool {
	for _, set := range n.CopyRRSetMap() {
		if set.Len() > 0 {
			return false
		}
	}
	return true
}
