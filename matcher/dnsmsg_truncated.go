package matcher

import (
	"github.com/miekg/dns"
)

const (
	DNSMatcherTruncated MatcherName = "Truncated"
	DNSMatcherTC        MatcherName = "TC"
)

func NewMatchDNSMsgTruncated(arg interface{}) (DnsMsgMatcher, error) {
	if ok, err := GetBool(arg); err != nil {
		return nil, err
	} else {
		return &matchDNSMsgTruncated{target: ok}, nil
	}
}

type matchDNSMsgTruncated struct {
	target bool
}

func (m *matchDNSMsgTruncated) Match(d *dns.Msg) bool {
	return d.Truncated == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherTruncated, NewMatchDNSMsgTruncated, UnmarshalBoolArg)
	RegisterDnsMsgMatcher(DNSMatcherTC, NewMatchDNSMsgTruncated, UnmarshalBoolArg)
}
