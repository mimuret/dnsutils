package matcher

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/mimuret/intcast"
	"github.com/pkg/errors"
)

const (
	DNSMatcherQType MatcherName = "QType"
)

func NewMatchDNSMsgQueryType(arg interface{}) (DnsMsgMatcher, error) {
	var (
		t     uint16
		exist bool
	)
	switch v := arg.(type) {
	case string:
		t, exist = dns.StringToType[v]
		if !exist {
			return nil, errors.Errorf("invalid qtype %s", v)
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

	return &matchDNSMsgQueryType{target: t}, nil
}

type matchDNSMsgQueryType struct {
	target uint16
}

func (m *matchDNSMsgQueryType) Match(d *dns.Msg) bool {
	if len(d.Question) == 0 {
		return false
	}
	return d.Question[0].Qtype == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherQType, NewMatchDNSMsgQueryType, UnmarshalStringArg)
}
