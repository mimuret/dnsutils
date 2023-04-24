package getter

import (
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

const (
	GetterQNameETLD DnsMsgGetterName = "QNameETLD"
)

func GetQNameETLDString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	if len(d.Question) == 0 {
		return MatchStringUnknown
	}
	return getQNameETLD(d.Question[0].Name)
}

func GetQNameETLD(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	if len(d.Question) == 0 {
		return nil
	}
	return getQNameETLD(d.Question[0].Name)
}

func getQNameETLD(name string) string {
	name, _ = publicsuffix.PublicSuffix(name)
	return name
}

func init() {
	RegisterDnsMsgGetFunc(GetterQNameETLD,
		func(d *dns.Msg) interface{} { return GetQNameETLD(d) },
		func(d *dns.Msg) string { return GetQNameETLDString(d) },
	)
}
