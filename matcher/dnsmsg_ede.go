package matcher

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/mimuret/intcast"
	"github.com/pkg/errors"
)

const (
	DNSMatcherEDE MatcherName = "EDE"
)

var (
	StringToEDE = map[string]uint16{
		"OtherError":                      0,
		"UnsupportedDNSKEYAlgorithm":      1,
		"UnsupportedDSDigestType":         2,
		"StaleAnswer":                     3,
		"ForgedAnswer":                    4,
		"DNSSECIndeterminate":             5,
		"DNSSECBogus":                     6,
		"SignatureExpired":                7,
		"SignatureNotYetValid":            8,
		"DNSKEYMissing":                   9,
		"RRSIGsMissing":                   10,
		"NoZoneKeyBitSet":                 11,
		"NSECMissing":                     12,
		"CachedError":                     13,
		"NotReady":                        14,
		"Blocked":                         15,
		"Censored":                        16,
		"Filtered":                        17,
		"Prohibited":                      18,
		"StaleNXDomainAnswer":             19,
		"NotAuthoritative":                20,
		"NotSupported":                    21,
		"NoReachableAuthority":            22,
		"NetworkError":                    23,
		"InvalidData":                     24,
		"SignatureExpiredbeforeValid":     25,
		"TooEarly":                        26,
		"UnsupportedNSEC3IterationsValue": 27,
		"Unabletoconformtopolicy":         28,
		"Synthesized":                     29,
	}
)

func NewMatchDNSMsgEDE(arg interface{}) (DnsMsgMatcher, error) {
	var (
		t     uint16
		exist bool
	)
	switch v := arg.(type) {
	case string:
		t, exist = StringToEDE[v]
		if !exist {
			return nil, errors.Errorf("unkown EDE %s", v)
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		i, err := intcast.GetUInt16(v)
		if err != nil {
			return nil, fmt.Errorf("invalid type args: %w", err)
		}
		t = i
	default:
		return nil, errors.Errorf("invalid type args %v", arg)
	}
	return &matchDNSMsgEDE{target: t}, nil
}

type matchDNSMsgEDE struct {
	target uint16
}

func (m *matchDNSMsgEDE) Match(d *dns.Msg) bool {
	if len(d.Extra) == 0 {
		// NO EDNS
		return false
	}
	opt, ok := d.Extra[0].(*dns.OPT)
	if !ok {
		return false
	}
	for _, opt := range opt.Option {
		ede, ok := opt.(*dns.EDNS0_EDE)
		if ok {
			if ede.InfoCode == m.target {
				return true
			}
		}
	}
	return false
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherEDE, NewMatchDNSMsgEDE, UnmarshalStringArg)
}
