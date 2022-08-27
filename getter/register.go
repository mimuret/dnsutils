package getter

import (
	"strings"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

const (
	MatchStringOn      = "on"
	MatchStringOff     = "off"
	MatchStringUnknown = "unknown"
)

type DnstapGetterName string

func (s DnstapGetterName) Get() DnstapGetterName {
	return DnstapGetterName(strings.ToUpper(string(s)))
}

type DnsMsgGetterName string

func (s DnsMsgGetterName) Get() DnsMsgGetterName {
	return DnsMsgGetterName(strings.ToUpper(string(s)))
}

type DnstapGetFunc func(*dnstap.Dnstap) interface{}
type DnsMsgGetFunc func(*dns.Msg) interface{}
type DnstapStrFunc func(*dnstap.Dnstap) string
type DnsMsgStrFunc func(*dns.Msg) string

var (
	dnstapGetter    = map[DnstapGetterName]DnstapGetFunc{}
	dnstapStrGetter = map[DnstapGetterName]DnstapStrFunc{}
	dnsMsgGetter    = map[DnsMsgGetterName]DnsMsgGetFunc{}
	dnsMsgStrGetter = map[DnsMsgGetterName]DnsMsgStrFunc{}
)

func RegisterDnstapGetFunc(name DnstapGetterName, getFunc DnstapGetFunc, strFunc DnstapStrFunc) {
	if name == "" {
		panic("name is empty")
	}
	if getFunc == nil || strFunc == nil {
		panic("invalid args for RegisterDnstapGetFunc")
	}
	dnstapGetter[name.Get()] = getFunc
	dnstapStrGetter[name.Get()] = strFunc
}

func RegisterDnsMsgGetFunc(name DnsMsgGetterName, getFunc DnsMsgGetFunc, strFunc DnsMsgStrFunc) {
	if name == "" {
		panic("name is empty")
	}
	if getFunc == nil || strFunc == nil {
		panic("invalid args for RegisterDnstapGetFunc")
	}
	dnsMsgGetter[name.Get()] = getFunc
	dnsMsgStrGetter[name.Get()] = strFunc
}
