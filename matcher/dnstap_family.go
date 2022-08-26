package matcher

import (
	"fmt"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/intcast"
	"github.com/pkg/errors"
)

const (
	DNSTAPMatcherMessageFamily = "MessageFamily"
)

func NewMatchMessageFamily(arg interface{}) (DnstapMatcher, error) {
	var (
		t dnstap.SocketFamily
	)
	switch v := arg.(type) {
	case string:
		vs, exist := dnstap.SocketFamily_value[v]
		if !exist {
			return nil, errors.Errorf("invalid opcode %s", v)
		}
		t = dnstap.SocketFamily(vs)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		i, err := intcast.GetInt32(v)
		if err != nil {
			return nil, fmt.Errorf("invalid type args: %w", err)
		}
		t = dnstap.SocketFamily(i)
	case dnstap.SocketFamily:
		t = v
	default:
		return nil, errors.Errorf("invalid family %v", arg)
	}
	return &matchMessageFamily{target: t}, nil
}

type matchMessageFamily struct {
	target dnstap.SocketFamily
}

func (m *matchMessageFamily) Match(d *dnstap.Dnstap) bool {
	if d.GetMessage() == nil {
		return false
	}
	return d.GetMessage().GetSocketFamily() == m.target
}

func init() {
	RegisterDnstapMatcher(DNSTAPMatcherMessageFamily, NewMatchMessageFamily, UnmarshalStringArg)
}
