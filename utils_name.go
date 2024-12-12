package dnsutils

import (
	"bytes"
	"slices"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

func isBorderChar(t byte) bool {
	return (t >= '0' && t <= '9') ||
		(t >= 'a' && t <= 'z') ||
		(t >= 'A' && t <= 'Z')
}

func isMiddleChar(t byte) bool {
	return isBorderChar(t) || t == '-'
}

// IsHostname checks if name is a valid RFC1123 hostname.
func IsHostname(name string) bool {
	buf := make([]byte, 255)
	offset, err := dns.PackDomainName(dns.CanonicalName(name), buf, 0, nil, false)
	if err != nil {
		// Not domain name
		return false
	}
	var i byte
	for i < byte(offset) {
		labelLen := buf[i]
		i++
		for j := byte(0); j < labelLen; j++ {
			if j == 0 || j == labelLen-1 {
				if !isBorderChar(buf[i+j]) {
					return false
				}
			} else {
				if !isMiddleChar(buf[i+j]) {
					return false
				}
			}
		}
		i += labelLen
	}
	return true
}

// Equals check that both names are equal.
// Input names can accept non-normalized name.
func Equals(a, b string) bool {
	bufa := make([]byte, 255)
	bufb := make([]byte, 255)
	_, err := dns.PackDomainName(dns.CanonicalName(a), bufa, 0, nil, false)
	if err != nil {
		return false
	}
	_, err = dns.PackDomainName(dns.CanonicalName(b), bufb, 0, nil, false)
	if err != nil {
		return false
	}

	return bytes.Equal(bufa, bufb)
}

// GetAllParentNames returns a name slice containing parent names and itself.
func GetAllParentNames(name string, level uint) ([]string, bool) {
	_, ok := dns.IsDomainName(name)
	if !ok {
		return nil, false
	}
	names := []string{}
	labels := dns.SplitDomainName(name)
	for i := len(labels) - int(level) - 1; i >= 0; i-- {
		names = append(names, dns.CanonicalName(strings.Join(labels[i:], ".")))
	}
	return names, true
}

// https://datatracker.ietf.org/doc/html/rfc4034#section-6.1
// SortNamesFunc returns sorted names
func SortNames(names []string) error {
	var err error
	sort.SliceStable(names, func(i, j int) bool {
		cmp, cErr := CompareName(names[i], names[j])
		if cErr != nil {
			err = cErr
		}
		return cmp < 0
	})
	if err != nil {
		return err
	}
	return nil
}

type rawSlice [][]byte

func SplitLabelsBytes(name string) (rawSlice, error) {
	buf := make([]byte, 255)
	offset, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		return nil, ErrBadName
	}
	var res rawSlice
	var i byte
	for i < byte(offset) {
		labelLen := buf[i]
		if labelLen == 0 {
			break
		}
		i++
		label := make([]byte, labelLen)
		copy(label, buf[i:i+labelLen])
		res = append(res, label)
		i = i + labelLen
	}
	return res, nil
}

// The result will be 0 if a == b, -1 if a < b, and +1 if a > b.
func CompareName(a, b string) (int, error) {
	al, err := SplitLabelsBytes(dns.CanonicalName(a))
	if err != nil {
		return 0, ErrBadName
	}
	bl, err := SplitLabelsBytes(dns.CanonicalName(b))
	if err != nil {
		return 0, ErrBadName
	}
	slices.Reverse(al)
	slices.Reverse(bl)
	for i := 0; i < len(al) && i < len(bl); i++ {
		if res := bytes.Compare(al[i], bl[i]); res != 0 {
			return res, nil
		}
	}
	if len(al) == len(bl) {
		return 0, nil
	}
	if len(al) > len(bl) {
		return 1, nil
	}
	return -1, nil
}
