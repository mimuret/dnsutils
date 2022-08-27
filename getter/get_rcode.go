package getter

import (
	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
)

const (
	GetterRcode DnsMsgGetterName = "Rcode"
)

func GetRcodeString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	return dnsutils.ConvertNumberToString(dns.RcodeToString, "RCODE", d.Rcode)
}

func GetRcode(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	return d.Rcode
}

func init() {
	RegisterDnsMsgGetFunc(GetterRcode, GetRcode, GetRcodeString)
}
