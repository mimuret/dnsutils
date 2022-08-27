package getter

import (
	"github.com/miekg/dns"
)

const (
	GetterCanonicalQName DnsMsgGetterName = "CanonicalQName"
)

func GetCanonicalQNameString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if len(d.Question) == 0 {
		return MatchStringUnknown
	}
	return dns.CanonicalName(d.Question[0].Name)
}

func GetCanonicalQName(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	if len(d.Question) == 0 {
		return nil
	}
	return dns.CanonicalName(d.Question[0].Name)
}

func init() {
	RegisterDnsMsgGetFunc(GetterCanonicalQName, GetCanonicalQName, GetCanonicalQNameString)
}
