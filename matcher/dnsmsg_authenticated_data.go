package matcher

import (
	"github.com/miekg/dns"
)

const (
	DNSMatcherAuthenticatedData MatcherName = "AuthenticatedData"
	DNSMatcherAD                MatcherName = "AD"
)

func NewMatchDNSMsgAuthenticatedData(arg interface{}) (DnsMsgMatcher, error) {
	if ok, err := GetBool(arg); err != nil {
		return nil, err
	} else {
		return &matchDNSMsgAuthenticatedData{target: ok}, nil
	}
}

type matchDNSMsgAuthenticatedData struct {
	target bool
}

func (m *matchDNSMsgAuthenticatedData) Match(d *dns.Msg) bool {
	return d.AuthenticatedData == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherAuthenticatedData, NewMatchDNSMsgAuthenticatedData, UnmarshalBoolArg)
	RegisterDnsMsgMatcher(DNSMatcherAD, NewMatchDNSMsgAuthenticatedData, UnmarshalBoolArg)
}
