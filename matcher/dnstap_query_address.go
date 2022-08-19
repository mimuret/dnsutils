package matcher

import (
	"net"

	dnstap "github.com/dnstap/golang-dnstap"
)

var (
	DNSTAPMatcherQueryAddress = "QueryAddress"
)

func NewMatchQueryAddress(arg interface{}) (DnstapMatcher, error) {
	if t, err := GetIPNet(arg); err != nil {
		return nil, err
	} else {
		return &matchQueryAddress{target: t}, nil
	}
}

type matchQueryAddress struct {
	target *net.IPNet
}

func (m *matchQueryAddress) Match(d *dnstap.Dnstap) bool {
	if d.GetMessage() == nil {
		return false
	}
	return m.target.Contains(d.GetMessage().GetQueryAddress())
}

func init() {
	RegisterDnstapMatcher(DNSTAPMatcherQueryAddress, NewMatchQueryAddress, UnmarshalStringArg)
}
