package matcher

import (
	"encoding/json"
	"fmt"
	"strings"
)

type MatchOp string

func (m MatchOp) Get() MatchOp {
	return MatchOp(strings.ToUpper(string(m)))
}

const (
	MatchOpAND MatchOp = "AND"
	MatchOpOR  MatchOp = "OR"
)

type MatcherType string

func (m MatcherType) Get() MatcherType {
	return MatcherType(strings.ToUpper(string(m)))
}
func (m MatcherType) Equals(c MatcherType) bool {
	return m.Get() == c.Get()
}

type MatcherName string

func (m MatcherName) Get() MatcherName {
	return MatcherName(strings.ToUpper(string(m)))
}

const (
	MatcherTypeDnstap MatcherType = "DNSTAP"
	MatcherTypeDnsMsg MatcherType = "DNS"
)

type Config struct {
	Op         MatchOp
	Inverse    bool
	Matchers   []MatcherConfig
	SubConfigs []Config
}

type MatcherConfig struct {
	Type MatcherType
	Name MatcherName
	Arg  interface{}
}

func (c *MatcherConfig) UnmarshalJSON(bs []byte) error {
	t := struct {
		Type MatcherType
		Name MatcherName
		Arg  json.RawMessage
	}{}

	if err := json.Unmarshal(bs, &t); err != nil {
		return fmt.Errorf("failed to parse json: %w", err)
	}

	var unmarshaler UnmarshalFunc
	var exist bool
	switch t.Type.Get() {
	case MatcherTypeDnstap:
		unmarshaler, exist = dnstapUnmarshaler[t.Name.Get()]
	case MatcherTypeDnsMsg:
		unmarshaler, exist = dnsMsgUnmarshaler[t.Name.Get()]
	default:
		return fmt.Errorf("unknown matcher type %s", t.Type)
	}
	if !exist {
		return fmt.Errorf("unknown matcher name %s", t.Type)
	}
	arg, err := unmarshaler(t.Arg)
	if err != nil {
		return fmt.Errorf("failed to parse arg: %w", err)
	}
	c.Type = t.Type
	c.Name = t.Name
	c.Arg = arg
	return nil
}
