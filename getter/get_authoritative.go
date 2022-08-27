package getter

import (
	"github.com/miekg/dns"
)

const (
	GetterAuthoritative DnsMsgGetterName = "Authoritative"
	GetterAA            DnsMsgGetterName = "AA"
)

func GetAuthoritativeString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if d.Authoritative {
		return MatchStringOn
	}
	return MatchStringOff
}

func GetAuthoritative(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	return d.Authoritative
}

func init() {
	RegisterDnsMsgGetFunc(GetterAuthoritative, GetAuthoritative, GetAuthoritativeString)
	RegisterDnsMsgGetFunc(GetterAA, GetAuthoritative, GetAuthoritativeString)
}
