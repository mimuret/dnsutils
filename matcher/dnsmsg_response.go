package matcher

import (
	"github.com/miekg/dns"
)

const (
	DNSMatcherResponse = "Response"
	DNSMatcherQR       = "QR"
)

func NewMatchDNSMsgResponse(arg interface{}) (DnsMsgMatcher, error) {
	if ok, err := GetBool(arg); err != nil {
		return nil, err
	} else {
		return &matchNSMsgResponse{target: ok}, nil
	}
}

type matchNSMsgResponse struct {
	target bool
}

func (m *matchNSMsgResponse) Match(d *dns.Msg) bool {
	return d.Response == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherResponse, NewMatchDNSMsgResponse, UnmarshalBoolArg)
	RegisterDnsMsgMatcher(DNSMatcherQR, NewMatchDNSMsgResponse, UnmarshalBoolArg)
}
