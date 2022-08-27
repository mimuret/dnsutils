package getter

import (
	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
)

const (
	GetterQType DnsMsgGetterName = "QType"
)

func GetQTypeString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if len(d.Question) == 0 {
		return MatchStringUnknown
	}
	return dnsutils.ConvertTypeToString(d.Question[0].Qtype)
}

func GetQType(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	if len(d.Question) == 0 {
		return nil
	}
	return d.Question[0].Qtype
}

func init() {
	RegisterDnsMsgGetFunc(GetterQType, GetQType, GetQTypeString)
}
