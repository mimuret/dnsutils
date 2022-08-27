package getter

import (
	"github.com/miekg/dns"
)

const (
	GetterRecursionAvailable DnsMsgGetterName = "RecursionAvailable"
	GetterRA                 DnsMsgGetterName = "RA"
)

func GetRecursionAvailableString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if d.RecursionAvailable {
		return MatchStringOn
	}
	return MatchStringOff
}

func GetRecursionAvailable(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	return d.RecursionAvailable
}

func init() {
	RegisterDnsMsgGetFunc(GetterRecursionAvailable, GetRecursionAvailable, GetRecursionAvailableString)
	RegisterDnsMsgGetFunc(GetterRA, GetRecursionAvailable, GetRecursionAvailableString)
}
