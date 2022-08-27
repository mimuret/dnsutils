package getter

import (
	"github.com/miekg/dns"
)

const (
	GetterQName DnsMsgGetterName = "QName"
)

func GetQNameString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if len(d.Question) == 0 {
		return MatchStringUnknown
	}
	return d.Question[0].Name
}

func GetQName(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	if len(d.Question) == 0 {
		return nil
	}
	return d.Question[0].Name
}

func init() {
	RegisterDnsMsgGetFunc(GetterQName, GetQName, GetQNameString)
}
