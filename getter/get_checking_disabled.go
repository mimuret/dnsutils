package getter

import (
	"github.com/miekg/dns"
)

const (
	GetterCheckingDisabled DnsMsgGetterName = "CheckingDisabled"
	GetterCD               DnsMsgGetterName = "CD"
)

func GetCheckingDisabledString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if d.CheckingDisabled {
		return MatchStringOn
	}
	return MatchStringOff
}

func GetCheckingDisabled(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	return d.CheckingDisabled
}

func init() {
	RegisterDnsMsgGetFunc(GetterCheckingDisabled, GetCheckingDisabled, GetCheckingDisabledString)
	RegisterDnsMsgGetFunc(GetterCD, GetCheckingDisabled, GetCheckingDisabledString)
}
