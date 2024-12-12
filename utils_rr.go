package dnsutils

import (
	"bytes"
	"fmt"
	"math"
	"sort"

	"github.com/miekg/dns"
)

func SortRRs(rrs []dns.RR) error {
	var err error
	sort.SliceStable(rrs, func(i, j int) bool {
		var res int
		res, err = CompareRR(rrs[i], rrs[j])
		return res < 0
	})
	return err
}

// The result will be 0 if a == b, -1 if a < b, and +1 if a > b.
func CompareRR(a, b dns.RR) (int, error) {
	// name
	res, err := CompareName(a.Header().Name, b.Header().Name)
	if err != nil {
		return 0, err
	}
	if res != 0 {
		return res, nil
	}

	// rrtype
	if a.Header().Rrtype != b.Header().Rrtype {
		if a.Header().Rrtype > b.Header().Rrtype {
			return 1, nil
		} else {
			return -1, nil
		}
	}

	// rdata
	bufA := make([]byte, math.MaxUint16)
	bufB := make([]byte, math.MaxUint16)
	offA, err := dns.PackRR(a, bufA, 0, nil, false)
	if err != nil {
		return 0, fmt.Errorf("failed to pack RR: %w", err)
	}
	offB, err := dns.PackRR(b, bufB, 0, nil, false)
	if err != nil {
		return 0, fmt.Errorf("failed to pack RR: %w", err)
	}
	// RDATA comparison because TTL is included in the comparison
	/// target when comparing bufA to bufB.
	return bytes.Compare(
		bufA[uint16(offA)-a.Header().Rdlength:offA],
		bufB[uint16(offB)-b.Header().Rdlength:offB],
	), nil
}
