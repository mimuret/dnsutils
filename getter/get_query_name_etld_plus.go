package getter

import (
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

const (
	GetterQNameETLDPlus DnsMsgGetterName = "QNameETLDPlus"
)

func GetQNameETLDPlusString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if len(d.Question) == 0 {
		return MatchStringUnknown
	}
	return getQNameETLDPlus(d.Question[0].Name)
}

func GetQNameETLDPlus(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	if len(d.Question) == 0 {
		return nil
	}
	return getQNameETLDPlus(d.Question[0].Name)
}

func getQNameETLDPlus(name string) string {
	name, err := publicsuffix.EffectiveTLDPlusOne(name)

	if err != nil {
		return MatchStringUnknown
	}
	return name
}

func init() {
	RegisterDnsMsgGetFunc(GetterQNameETLDPlus,
		func(d *dns.Msg) interface{} { return GetQNameETLDPlus(d) },
		func(d *dns.Msg) string { return GetQNameETLDPlusString(d) },
	)
}
