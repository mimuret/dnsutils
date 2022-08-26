package matcher

import (
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

const (
	DNSMatcherStatic    = "Static"
	DNSTAPMatcherStatic = "Static"
)

func NewMatchDnstapStatic(arg interface{}) (DnstapMatcher, error) {
	if ok, err := GetBool(arg); err != nil {
		return nil, err
	} else {
		return &matchStaticDnstap{result: ok}, nil
	}
}

type matchStaticDnstap struct {
	result bool
}

func (m *matchStaticDnstap) Match(*dnstap.Dnstap) bool {
	return m.result
}

func NewMatchDNSMsgStatic(arg interface{}) (DnsMsgMatcher, error) {
	if ok, err := GetBool(arg); err != nil {
		return nil, err
	} else {
		return &matchStaticDNSMsg{result: ok}, nil
	}
}

type matchStaticDNSMsg struct {
	result bool
}

func (m *matchStaticDNSMsg) Match(*dns.Msg) bool {
	return m.result
}

func init() {
	RegisterDnstapMatcher(DNSMatcherStatic, NewMatchDnstapStatic, UnmarshalBoolArg)
	RegisterDnsMsgMatcher(DNSTAPMatcherStatic, NewMatchDNSMsgStatic, UnmarshalBoolArg)
}
