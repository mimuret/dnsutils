package getter

import (
	"net"

	dnstap "github.com/dnstap/golang-dnstap"
)

const (
	GetterResponseAddress DnstapGetterName = "ResponseAddress"
)

func GetResponseAddressString(d *dnstap.Dnstap) string {
	if d == nil {
		return MatchStringUnknown
	}
	msg := d.GetMessage()
	if msg == nil {
		return MatchStringUnknown
	}
	ip := net.IP(msg.GetResponseAddress())
	if ip == nil {
		return MatchStringUnknown
	}
	return ip.String()
}

func GetResponseAddress(d *dnstap.Dnstap) interface{} {
	if d == nil {
		return nil
	}
	msg := d.GetMessage()
	if msg == nil {
		return nil
	}
	return msg.GetResponseAddress()
}

func init() {
	RegisterDnstapGetFunc(GetterResponseAddress, GetResponseAddress, GetResponseAddressString)
}
