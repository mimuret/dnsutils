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

var (
	MatchOpAND MatchOp = "AND"
	MatchOpOR  MatchOp = "OR"
)

type MatcherType string

func (m MatcherType) Get() MatcherType {
	return MatcherType(strings.ToUpper(string(m)))
}

var (
	MatcherTypeDnstap MatcherType = "DNSTAP"
	MatcherTypeDnsMsg MatcherType = "DNS"
)

type Config struct {
	Op         MatchOp
	Matchers   []MatcherConfig
	SubConfigs []Config
}
type MatcherConfig struct {
	Type MatcherType
	Name string
	Arg  interface{}
}

func (c *MatcherConfig) UnmarshalJSON(bs []byte) error {
	t := struct {
		Type MatcherType
		Name string
		Arg  json.RawMessage
	}{}

	if err := json.Unmarshal(bs, &t); err != nil {
		return fmt.Errorf("failed to parse json: %w", err)
	}

	var unmarshaler UnmarshalFunc
	var exist bool
	switch t.Type {
	case MatcherTypeDnstap:
		unmarshaler, exist = dnstapUnmarshaler[t.Name]
	case MatcherTypeDnsMsg:
		unmarshaler, exist = dnsMsgUnmarshaler[t.Name]
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
