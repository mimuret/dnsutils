package getter

import (
	"net"
	"strconv"

	"github.com/miekg/dns"
)

const (
	GetterECSQuery      DnsMsgGetterName = "ECSQuery"
	GetterECSResponse   DnsMsgGetterName = "ECSResponse"
	GetterECSSourceMask DnsMsgGetterName = "ECSSourceMask"
	GetterECSScopeMask  DnsMsgGetterName = "ECSScopeMask"
)

func GetECSQueryString(d *dns.Msg) string {
	ipnet := GetECSQuery(d)
	if ipnet == nil {
		return MatchStringUnknown
	}
	return ipnet.(*net.IPNet).String()
}

func GetECSQuery(d *dns.Msg) interface{} {
	ecs := getECS(d)
	if ecs == nil {
		return nil
	}
	maxCIDR := 128
	if ecs.Family == 1 {
		maxCIDR = 32
	}
	return &net.IPNet{IP: ecs.Address, Mask: net.CIDRMask(int(ecs.SourceNetmask), maxCIDR)}
}

func GetECSResponseString(d *dns.Msg) string {
	ipnet := GetECSResponse(d)
	if ipnet == nil {
		return MatchStringUnknown
	}
	return ipnet.(*net.IPNet).String()
}

func GetECSResponse(d *dns.Msg) interface{} {
	ecs := getECS(d)
	if ecs == nil {
		return nil
	}
	maxCIDR := 128
	if ecs.Family == 1 {
		maxCIDR = 32
	}
	return &net.IPNet{IP: ecs.Address, Mask: net.CIDRMask(int(ecs.SourceScope), maxCIDR)}
}

func GetECSSourceMaskString(d *dns.Msg) string {
	netmask := GetECSSourceMask(d)
	if netmask == nil {
		return MatchStringUnknown
	}
	n := netmask.(uint8)
	return strconv.FormatUint(uint64(n), 10)
}

func GetECSSourceMask(d *dns.Msg) interface{} {
	ecs := getECS(d)
	if ecs == nil {
		return nil
	}
	return ecs.SourceNetmask
}

func GetECSScopeMaskString(d *dns.Msg) string {
	scope := GetECSScopeMask(d)
	if scope == nil {
		return MatchStringUnknown
	}
	n := scope.(uint8)
	return strconv.FormatUint(uint64(n), 10)
}

func GetECSScopeMask(d *dns.Msg) interface{} {
	ecs := getECS(d)
	if ecs == nil {
		return nil
	}
	return ecs.SourceScope
}

func getECS(d *dns.Msg) *dns.EDNS0_SUBNET {
	if d == nil {
		return nil
	}
	if len(d.Extra) > 0 {
		for _, rr := range d.Extra {
			if optrr, ok := rr.(*dns.OPT); ok {
				for _, edns0opt := range optrr.Option {
					if ecs, ok := edns0opt.(*dns.EDNS0_SUBNET); ok {
						return ecs
					}
				}
			}
		}
	}
	return nil
}

func init() {
	RegisterDnsMsgGetFunc(GetterECSQuery, GetECSQuery, GetECSQueryString)
	RegisterDnsMsgGetFunc(GetterECSResponse, GetECSResponse, GetECSResponseString)
	RegisterDnsMsgGetFunc(GetterECSSourceMask, GetECSSourceMask, GetECSSourceMaskString)
	RegisterDnsMsgGetFunc(GetterECSScopeMask, GetECSScopeMask, GetECSScopeMaskString)
}
