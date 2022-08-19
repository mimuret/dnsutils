package matcher

import (
	"github.com/miekg/dns"
)

var (
	DNSMatcherRecursionDesired = "RecursionDesired"
	DNSMatcherRD               = "RD"
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
