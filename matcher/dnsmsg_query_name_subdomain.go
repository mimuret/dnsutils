package matcher

import (
	"bytes"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

const (
	DNSMatcherQNameSubDomain MatcherName = "QNameSubDomain"
)

func NewMatchDNSMsgQueryNameSubDomain(arg interface{}) (DnsMsgMatcher, error) {
	qName, ok := arg.(string)
	if !ok {
		return nil, errors.Errorf("invalid type args %v", arg)
	}
	buf := make([]byte, 255)
	offset, err := dns.PackDomainName(dns.CanonicalName(qName), buf, 0, nil, false)
	if err != nil {
		return nil, errors.Wrap(err, "invalid domain name")
	}
	return &matchDNSMsgQueryNameSubDomain{target: buf[:offset], offset: offset}, nil
}

type matchDNSMsgQueryNameSubDomain struct {
	target []byte
	offset int
}

func (m *matchDNSMsgQueryNameSubDomain) Match(d *dns.Msg) bool {
	if len(d.Question) == 0 {
		return false
	}
	buf := make([]byte, 255)
	offset, err := dns.PackDomainName(dns.CanonicalName(d.Question[0].Name), buf, 0, nil, false)
	if err != nil {
		return false
	}
	buf = buf[:offset]
	if len(buf) < len(m.target) {
		return false
	}
	return bytes.Equal(m.target, buf[offset-m.offset:])
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherQNameSubDomain, NewMatchDNSMsgQueryNameSubDomain, UnmarshalStringArg)
}
