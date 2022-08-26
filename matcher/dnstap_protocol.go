package matcher

import (
	"fmt"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/intcast"
	"github.com/pkg/errors"
)

const (
	DNSTAPMatcherMessageProtocol MatcherName = "MessageProtocol"
)

func NewMatchMessageProtocol(arg interface{}) (DnstapMatcher, error) {
	var (
		t dnstap.SocketProtocol
	)
	switch v := arg.(type) {
	case string:
		vs, exist := dnstap.SocketProtocol_value[v]
		if !exist {
			return nil, errors.Errorf("invalid opcode %s", v)
		}
		t = dnstap.SocketProtocol(vs)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		i, err := intcast.GetInt32(v)
		if err != nil {
			return nil, fmt.Errorf("invalid type args: %w", err)
		}
		t = dnstap.SocketProtocol(i)
	case dnstap.SocketProtocol:
		t = v
	default:
		return nil, errors.Errorf("invalid family %v", arg)
	}
	return &matchMessageProtocol{target: t}, nil
}

type matchMessageProtocol struct {
	target dnstap.SocketProtocol
}

func (m *matchMessageProtocol) Match(d *dnstap.Dnstap) bool {
	if d.GetMessage() == nil {
		return false
	}
	return d.GetMessage().GetSocketProtocol() == m.target
}

func init() {
	RegisterDnstapMatcher(DNSTAPMatcherMessageProtocol, NewMatchMessageProtocol, UnmarshalStringArg)
}
