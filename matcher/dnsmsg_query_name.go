package matcher

import (
	"bytes"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

const (
	DNSMatcherQName MatcherName = "QName"
)

func NewMatchDNSMsgQueryName(arg interface{}) (DnsMsgMatcher, error) {
	qName, ok := arg.(string)
	if !ok {
		return nil, errors.Errorf("invalid type args %v", arg)
	}
	buf := make([]byte, 255)
	_, err := dns.PackDomainName(dns.CanonicalName(qName), buf, 0, nil, false)
	if err != nil {
		return nil, errors.Wrap(err, "invalid domain name")
	}
	return &matchDNSMsgQueryName{target: buf}, nil
}

type matchDNSMsgQueryName struct {
	target []byte
}

func (m *matchDNSMsgQueryName) Match(d *dns.Msg) bool {
	if len(d.Question) == 0 {
		return false
	}
	buf := make([]byte, 255)
	_, err := dns.PackDomainName(dns.CanonicalName(d.Question[0].Name), buf, 0, nil, false)
	if err != nil {
		return false
	}
	return bytes.Equal(m.target, buf)
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherQName, NewMatchDNSMsgQueryName, UnmarshalStringArg)
}
