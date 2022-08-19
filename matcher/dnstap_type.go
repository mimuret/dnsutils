package matcher

import (
	"fmt"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/intcast"
	"github.com/pkg/errors"
)

var (
	DNSTAPMatcherMessageType = "MessageType"
)

func NewMatchMessageType(arg interface{}) (DnstapMatcher, error) {
	var (
		t dnstap.Message_Type
	)
	switch v := arg.(type) {
	case string:
		vs, exist := dnstap.Message_Type_value[v]
		if !exist {
			return nil, errors.Errorf("invalid message type %s", v)
		}
		t = dnstap.Message_Type(vs)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		i, err := intcast.GetInt32(v)
		if err != nil {
			return nil, fmt.Errorf("invalid type args: %w", err)
		}
		t = dnstap.Message_Type(i)
	case dnstap.Message_Type:
		t = v
	default:
		return nil, errors.Errorf("invalid message type %v", arg)
	}
	return &matchMessageType{target: t}, nil
}

type matchMessageType struct {
	target dnstap.Message_Type
}

func (m *matchMessageType) Match(d *dnstap.Dnstap) bool {
	if d.GetMessage() == nil {
		return false
	}
	return d.GetMessage().GetType() == m.target
}

func init() {
	RegisterDnstapMatcher(DNSTAPMatcherMessageType, NewMatchMessageType, UnmarshalStringArg)
}
