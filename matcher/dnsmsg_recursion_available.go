package matcher

import (
	"github.com/miekg/dns"
)

var (
	DNSMatcherRecursionAvailable = "RecursionAvailable"
	DNSMatcherRA                 = "RA"
)

func NewMatchDNSMsgRecursionAvailable(arg interface{}) (DnsMsgMatcher, error) {
	if ok, err := GetBool(arg); err != nil {
		return nil, err
	} else {
		return &matchDNSMsgRecursionAvailable{target: ok}, nil
	}
}

type matchDNSMsgRecursionAvailable struct {
	target bool
}

func (m *matchDNSMsgRecursionAvailable) Match(d *dns.Msg) bool {
	return d.RecursionAvailable == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherRecursionAvailable, NewMatchDNSMsgRecursionAvailable, UnmarshalBoolArg)
	RegisterDnsMsgMatcher(DNSMatcherRA, NewMatchDNSMsgRecursionAvailable, UnmarshalBoolArg)
}
