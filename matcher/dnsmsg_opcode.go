package matcher

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/mimuret/intcast"
	"github.com/pkg/errors"
)

var (
	DNSMatcherOpcode = "Opcode"
)

func NewMatchDNSMsgOpcode(arg interface{}) (DnsMsgMatcher, error) {
	var (
		t     int
		exist bool
	)
	switch v := arg.(type) {
	case string:
		t, exist = dns.StringToOpcode[v]
		if !exist {
			return nil, errors.Errorf("invalid opcode %s", v)
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		i, err := intcast.GetInt(v)
		if err != nil {
			return nil, fmt.Errorf("invalid type args: %w", err)
		}
		t = i
	default:
		return nil, errors.Errorf("invalid type args %v", arg)
	}

	return &matchDNSMsgOpcode{target: t}, nil
}

type matchDNSMsgOpcode struct {
	target int
}

func (m *matchDNSMsgOpcode) Match(d *dns.Msg) bool {
	return d.Opcode == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherOpcode, NewMatchDNSMsgOpcode, UnmarshalStringArg)
}
