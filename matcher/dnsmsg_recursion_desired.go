package matcher

import (
	"github.com/miekg/dns"
)

const (
	DNSMatcherRecursionDesired MatcherName = "RecursionDesired"
	DNSMatcherRD               MatcherName = "RD"
)

func NewMatchDNSMsgRecursionDesired(arg interface{}) (DnsMsgMatcher, error) {
	if ok, err := GetBool(arg); err != nil {
		return nil, err
	} else {
		return &matchDNSMsgRecursionDesired{target: ok}, nil
	}
}

type matchDNSMsgRecursionDesired struct {
	target bool
}

func (m *matchDNSMsgRecursionDesired) Match(d *dns.Msg) bool {
	return d.RecursionDesired == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherRecursionDesired, NewMatchDNSMsgRecursionDesired, UnmarshalBoolArg)
	RegisterDnsMsgMatcher(DNSMatcherRD, NewMatchDNSMsgRecursionDesired, UnmarshalBoolArg)
}
