package matcher

import (
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/intcast"
	"github.com/pkg/errors"
)

var (
	DNSTAPMatcherQueryPort = "QueryPort"
)

func NewMatchQueryPort(arg interface{}) (DnstapMatcher, error) {
	if t, err := intcast.GetUInt32(arg); err != nil {
		return nil, errors.Errorf("invalid Query Port %v", arg)
	} else {
		return &matchQueryPort{target: t}, nil
	}
}

type matchQueryPort struct {
	target uint32
}

func (m *matchQueryPort) Match(d *dnstap.Dnstap) bool {
	if d.GetMessage() == nil {
		return false
	}
	return d.GetMessage().GetQueryPort() == m.target
}

func init() {
	RegisterDnstapMatcher(DNSTAPMatcherQueryPort, NewMatchQueryPort, UnmarshalUint32Arg)
}
