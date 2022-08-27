package getter

import (
	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
)

const (
	GetterQClass DnsMsgGetterName = "QClass"
)

func GetQClassString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if len(d.Question) == 0 {
		return MatchStringUnknown
	}
	return dnsutils.ConvertClassToString(dns.Class(d.Question[0].Qclass))
}

func GetQClass(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	if len(d.Question) == 0 {
		return nil
	}
	return d.Question[0].Qclass
}

func init() {
	RegisterDnsMsgGetFunc(GetterQClass, GetQClass, GetQClassString)
}
