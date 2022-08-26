package matcher

import (
	"fmt"
	"regexp"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

const (
	DNSMatcherQNameRegexp MatcherName = "QNameRegexp"
)

func NewMatchDNSMsgQueryNameRegexp(arg interface{}) (DnsMsgMatcher, error) {
	var (
		t   *regexp.Regexp
		err error
	)
	switch v := arg.(type) {
	case string:
		t, err = regexp.Compile(v)
		if err != nil {
			return nil, fmt.Errorf("invalid qname regexp: %s err: %w", v, err)
		}
	case *regexp.Regexp:
		t = v
	default:
		return nil, errors.Errorf("invalid type args %v", arg)
	}
	return &matchDNSMsgQueryNameRegexp{matcher: t}, nil
}

type matchDNSMsgQueryNameRegexp struct {
	matcher *regexp.Regexp
}

func (m *matchDNSMsgQueryNameRegexp) Match(d *dns.Msg) bool {
	if len(d.Question) == 0 {
		return false
	}
	return m.matcher.MatchString(d.Question[0].Name)
}

func init() {
	RegisterDnsMsgMatcher(DNSMatcherQNameRegexp, NewMatchDNSMsgQueryNameRegexp, UnmarshalStringArg)
}
