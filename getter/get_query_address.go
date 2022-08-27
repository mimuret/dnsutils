package getter

import (
	"net"

	dnstap "github.com/dnstap/golang-dnstap"
)

const (
	GetterQueryAddress DnstapGetterName = "QueryAddress"
)

func GetQueryAddressString(d *dnstap.Dnstap) string {
	if d == nil {
		return MatchStringUnknown
	}
	msg := d.GetMessage()
	if msg == nil {
		return MatchStringUnknown
	}
	ip := net.IP(msg.GetQueryAddress())
	if ip == nil {
		return MatchStringUnknown
	}
	return ip.String()
}

func GetQueryAddress(d *dnstap.Dnstap) interface{} {
	if d == nil {
		return nil
	}
	msg := d.GetMessage()
	if msg == nil {
		return nil
	}
	return msg.GetQueryAddress()
}

func init() {
	RegisterDnstapGetFunc(GetterQueryAddress, GetQueryAddress, GetQueryAddressString)
}
