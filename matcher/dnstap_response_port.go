package matcher

import (
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/intcast"
	"github.com/pkg/errors"
)

const (
	DNSTAPMatcherResponsePort MatcherName = "ResponsePort"
)

func NewMatchResponsePort(arg interface{}) (DnstapMatcher, error) {
	if t, err := intcast.GetUInt32(arg); err != nil {
		return nil, errors.Errorf("invalid Response Port %v", arg)
	} else {
		return &matchResponsePort{target: t}, nil
	}
}

type matchResponsePort struct {
	target uint32
}

func (m *matchResponsePort) Match(d *dnstap.Dnstap) bool {
	if d.GetMessage() == nil {
		return false
	}
	return d.GetMessage().GetResponsePort() == m.target
}

func init() {
	RegisterDnstapMatcher(DNSTAPMatcherResponsePort, NewMatchResponsePort, UnmarshalUint32Arg)
}
