package dnsutils

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/mimuret/intcast"
	"golang.org/x/exp/constraints"
)

// ConvertStringToType returns uint16 dns rrtype by string
// If it failed to parse, returns ErrInvalid
func ConvertStringToType(s string) (uint16, error) {
	return ConvertToStringToNumber(dns.StringToType, "TYPE", s)
}

// ConvertStringToClass returns dns.Class by string
// If it failed to parse, returns ErrInvalid
func ConvertStringToClass(s string) (dns.Class, error) {
	class, err := ConvertToStringToNumber(dns.StringToClass, "CLASS", s)
	return dns.Class(class), err
}

func ConvertToStringToNumber[T constraints.Integer](def map[string]T, prefix, s string) (T, error) {
	var (
		t  T
		ok bool
	)
	if t, ok = def[s]; ok {
		return t, nil
	}
	if strings.HasPrefix(s, prefix) {
		v := strings.TrimLeft(s, prefix)
		res, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, ErrInvalid
		}
		if err := intcast.Cast(res, &t); err != nil {
			return 0, ErrInvalid
		}
		return t, nil
	}
	return 0, ErrInvalid
}

// ConvertTypeToString returns RRType string by uint16 dns rrtype.
func ConvertTypeToString(i uint16) string {
	return ConvertNumberToString(dns.TypeToString, "TYPE", i)
}

// ConvertClassToString returns DNS Class string by dns.Class
func ConvertClassToString(i dns.Class) string {
	return ConvertNumberToString(dns.ClassToString, "CLASS", uint16(i))
}

func ConvertNumberToString[T constraints.Integer](def map[T]string, prefix string, i T) string {
	if s, ok := def[i]; ok {
		return s
	}
	return prefix + strconv.FormatUint(uint64(i), 10)
}
