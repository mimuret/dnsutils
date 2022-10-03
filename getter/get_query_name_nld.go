package getter

import (
	"strings"

	"github.com/miekg/dns"
)

const (
	GetterQNameTLD DnsMsgGetterName = "QNameTLD"
	GetterQNameSLD DnsMsgGetterName = "QNameSLD"
	GetterQName1LD DnsMsgGetterName = "QName1LD"
	GetterQName2LD DnsMsgGetterName = "QName2LD"
	GetterQName3LD DnsMsgGetterName = "QName3LD"
	GetterQName4LD DnsMsgGetterName = "QName4LD"
	GetterQName5LD DnsMsgGetterName = "QName5LD"
)

func GetQNameXLDString(d *dns.Msg, n int) string {
	if d == nil {
		return MatchStringUnknown
	}
	if len(d.Question) == 0 {
		return MatchStringUnknown
	}
	return getXLDName(d.Question[0].Name, n)
}

func GetQNameXLD(d *dns.Msg, n int) interface{} {
	if d == nil {
		return nil
	}
	if len(d.Question) == 0 {
		return nil
	}
	return getXLDName(d.Question[0].Name, n)
}

func getXLDName(name string, n int) string {
	name = dns.CanonicalName(name)
	labels := dns.SplitDomainName(name)
	if len(labels)-n < 0 {
		return name
	}
	return dns.CanonicalName(strings.Join(labels[len(labels)-n:], "."))
}

func init() {
	RegisterDnsMsgGetFunc(GetterQNameTLD,
		func(d *dns.Msg) interface{} { return GetQNameXLD(d, 1) },
		func(d *dns.Msg) string { return GetQNameXLDString(d, 1) },
	)
	RegisterDnsMsgGetFunc(GetterQNameSLD,
		func(d *dns.Msg) interface{} { return GetQNameXLD(d, 2) },
		func(d *dns.Msg) string { return GetQNameXLDString(d, 2) },
	)
	RegisterDnsMsgGetFunc(GetterQName1LD,
		func(d *dns.Msg) interface{} { return GetQNameXLD(d, 1) },
		func(d *dns.Msg) string { return GetQNameXLDString(d, 1) },
	)
	RegisterDnsMsgGetFunc(GetterQName2LD,
		func(d *dns.Msg) interface{} { return GetQNameXLD(d, 2) },
		func(d *dns.Msg) string { return GetQNameXLDString(d, 2) },
	)
	RegisterDnsMsgGetFunc(GetterQName3LD,
		func(d *dns.Msg) interface{} { return GetQNameXLD(d, 3) },
		func(d *dns.Msg) string { return GetQNameXLDString(d, 3) },
	)
	RegisterDnsMsgGetFunc(GetterQName4LD,
		func(d *dns.Msg) interface{} { return GetQNameXLD(d, 4) },
		func(d *dns.Msg) string { return GetQNameXLDString(d, 4) },
	)
	RegisterDnsMsgGetFunc(GetterQName5LD,
		func(d *dns.Msg) interface{} { return GetQNameXLD(d, 5) },
		func(d *dns.Msg) string { return GetQNameXLDString(d, 5) },
	)
}
