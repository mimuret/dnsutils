package matcher

import (
	"net"

	dnstap "github.com/dnstap/golang-dnstap"
)

var (
	DNSTAPMatcherResponseAddress = "ResponseAddress"
)

func NewMatchResponseAddress(arg interface{}) (DnstapMatcher, error) {
	if t, err := GetIPNet(arg); err != nil {
		return nil, err
	} else {
		return &matchResponseAddress{target: t}, nil
	}
}

type matchResponseAddress struct {
	target *net.IPNet
}

func (m *matchResponseAddress) Match(d *dnstap.Dnstap) bool {
	if d.GetMessage() == nil {
		return false
	}
	return m.target.Contains(d.GetMessage().GetResponseAddress())
}

func init() {
	RegisterDnstapMatcher(DNSTAPMatcherResponseAddress, NewMatchResponseAddress, UnmarshalStringArg)
}
