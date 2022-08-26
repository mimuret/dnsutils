package matcher

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/mimuret/intcast"
	"github.com/pkg/errors"
)

const (
	DNSMatcherRcode MatcherName = "Rcode"
)

func NewMatchDNSMsgRcode(arg interface{}) (DnsMsgMatcher, error) {
	var (
		t     int
		exist bool
	)
	switch v := arg.(type) {
	case string:
		t, exist = dns.StringToRcode[v]
		if !exist {
			return nil, errors.Errorf("invalid rcode %s", v)
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

	return &matchDNSMsgRcode{target: t}, nil
}

type matchDNSMsgRcode struct {
	target int
}

func (m *matchDNSMsgRcode) Match(d *dns.Msg) bool {
	return d.Rcode == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherRcode, NewMatchDNSMsgRcode, UnmarshalStringArg)
}
