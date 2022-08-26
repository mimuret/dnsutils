package matcher

import (
	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

const (
	DNSMatcherQName = "QName"
)

func NewMatchDNSMsgQueryName(arg interface{}) (DnsMsgMatcher, error) {
	qName, ok := arg.(string)
	if !ok {
		return nil, errors.Errorf("invalid type args %v", arg)
	}
	return &matchDNSMsgQueryName{target: qName}, nil
}

type matchDNSMsgQueryName struct {
	target string
}

func (m *matchDNSMsgQueryName) Match(d *dns.Msg) bool {
	if len(d.Question) == 0 {
		return false
	}
	return d.Question[0].Name == m.target
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherQName, NewMatchDNSMsgQueryName, UnmarshalStringArg)
}
