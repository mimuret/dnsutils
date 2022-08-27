package getter

import (
	"github.com/miekg/dns"
)

const (
	GetterResponse DnsMsgGetterName = "Response"
	GetterQR       DnsMsgGetterName = "QR"
)

func GetResponseString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if d.Response {
		return MatchStringOn
	}
	return MatchStringOff
}

func GetResponse(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	return d.Response
}

func init() {
	RegisterDnsMsgGetFunc(GetterResponse, GetResponse, GetResponseString)
	RegisterDnsMsgGetFunc(GetterQR, GetResponse, GetResponseString)
}
