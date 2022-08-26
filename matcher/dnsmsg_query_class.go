package matcher

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/mimuret/intcast"
	"github.com/pkg/errors"
)

const (
	DNSMatcherQClass MatcherName = "QClass"
)

func NewMatchDNSMsgQueryClass(arg interface{}) (DnsMsgMatcher, error) {
	var (
		t     uint16
		exist bool
	)
	switch v := arg.(type) {
	case string:
		t, exist = dns.StringToClass[v]
		if !exist {
			return nil, errors.Errorf("invalid qclass %s", v)
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
	return &matchDNSMsgQueryClass{target: t}, nil
}

type matchDNSMsgQueryClass struct {
	target uint16
}

func (m *matchDNSMsgQueryClass) Match(d *dns.Msg) bool {
	if len(d.Question) == 0 {
		return false
	}
	return d.Question[0].Qclass == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherQClass, NewMatchDNSMsgQueryClass, UnmarshalStringArg)
}
