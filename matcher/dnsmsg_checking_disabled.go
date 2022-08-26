package matcher

import (
	"github.com/miekg/dns"
)

const (
	DNSMatcherCheckingDisabled = "CheckingDisabled"
	DNSMatcherCD               = "CD"
)

func NewMatchDNSMsgCheckingDisabled(arg interface{}) (DnsMsgMatcher, error) {
	if ok, err := GetBool(arg); err != nil {
		return nil, err
	} else {
		return &matchDNSMsgCheckingDisabled{target: ok}, nil
	}
}

type matchDNSMsgCheckingDisabled struct {
	target bool
}

func (m *matchDNSMsgCheckingDisabled) Match(d *dns.Msg) bool {
	return d.CheckingDisabled == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherCheckingDisabled, NewMatchDNSMsgCheckingDisabled, UnmarshalBoolArg)
	RegisterDnsMsgMatcher(DNSMatcherCD, NewMatchDNSMsgCheckingDisabled, UnmarshalBoolArg)
}
