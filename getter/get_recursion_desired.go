package getter

import (
	"github.com/miekg/dns"
)

const (
	GetterRecursionDesired DnsMsgGetterName = "RecursionDesired"
	GetterRD               DnsMsgGetterName = "RD"
)

func GetRecursionDesiredString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if d.RecursionDesired {
		return MatchStringOn
	}
	return MatchStringOff
}

func GetRecursionDesired(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	return d.RecursionDesired
}

func init() {
	RegisterDnsMsgGetFunc(GetterRecursionDesired, GetRecursionDesired, GetRecursionDesiredString)
	RegisterDnsMsgGetFunc(GetterRD, GetRecursionDesired, GetRecursionDesiredString)
}
