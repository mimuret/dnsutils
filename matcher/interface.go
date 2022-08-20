package matcher

import (
	"encoding/json"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

type DnstapMatcher interface {
	Match(*dnstap.Dnstap) bool
}

type DnsMsgMatcher interface {
	Match(*dns.Msg) bool
}

type UnmarshalFunc func(json.RawMessage) (interface{}, error)
type NewDnstapMatcher func(interface{}) (DnstapMatcher, error)
type NewDnsMsgMatcher func(interface{}) (DnsMsgMatcher, error)
