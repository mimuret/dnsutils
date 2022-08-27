package getter

import (
	"github.com/miekg/dns"
)

const (
	GetterTruncated DnsMsgGetterName = "Truncated"
	GetterTC        DnsMsgGetterName = "TC"
)

func GetTruncatedString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if d.Truncated {
		return MatchStringOn
	}
	return MatchStringOff
}

func GetTruncated(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	return d.Truncated
}

func init() {
	RegisterDnsMsgGetFunc(GetterTruncated, GetTruncated, GetTruncatedString)
	RegisterDnsMsgGetFunc(GetterTC, GetTruncated, GetTruncatedString)
}
