package matcher

import (
	"github.com/miekg/dns"
)

const (
	DNSMatcherAuthoritative MatcherName = "Authoritative"
	DNSMatcherAA            MatcherName = "AA"
)

func NewMatchDNSMsgAuthoritative(arg interface{}) (DnsMsgMatcher, error) {
	if ok, err := GetBool(arg); err != nil {
		return nil, err
	} else {
		return &matchDNSMsgAuthoritative{target: ok}, nil
	}
}

type matchDNSMsgAuthoritative struct {
	target bool
}

func (m *matchDNSMsgAuthoritative) Match(d *dns.Msg) bool {
	return d.Authoritative == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherAuthoritative, NewMatchDNSMsgAuthoritative, UnmarshalBoolArg)
	RegisterDnsMsgMatcher(DNSMatcherAA, NewMatchDNSMsgAuthoritative, UnmarshalBoolArg)
}
