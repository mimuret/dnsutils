package getter

import (
	"github.com/miekg/dns"
)

const (
	GetterAuthenticatedData DnsMsgGetterName = "AuthenticatedData"
	GetterAD                DnsMsgGetterName = "AD"
)

func GetAuthenticatedDataString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if d.AuthenticatedData {
		return MatchStringOn
	}
	return MatchStringOff
}

func GetAuthenticatedData(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	return d.AuthenticatedData
}

func init() {
	RegisterDnsMsgGetFunc(GetterAuthenticatedData, GetAuthenticatedData, GetAuthenticatedDataString)
	RegisterDnsMsgGetFunc(GetterAD, GetAuthenticatedData, GetAuthenticatedDataString)
}
