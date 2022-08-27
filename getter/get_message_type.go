package getter

import (
	dnstap "github.com/dnstap/golang-dnstap"
)

const (
	GetterMessageProtocol DnstapGetterName = "MessageProtocol"
	GetterSocketProtocol  DnstapGetterName = "SocketProtocol"
)

func GetSocketProtocolString(d *dnstap.Dnstap) string {
	if d == nil {
		return MatchStringUnknown
	}
	msg := d.GetMessage()
	if msg == nil {
		return MatchStringUnknown
	}
	return msg.GetSocketProtocol().String()
}

func GetSocketProtocol(d *dnstap.Dnstap) interface{} {
	if d == nil {
		return nil
	}
	msg := d.GetMessage()
	if msg == nil {
		return nil
	}
	return msg.GetSocketProtocol()
}

func init() {
	RegisterDnstapGetFunc(GetterSocketProtocol, GetSocketProtocol, GetSocketProtocolString)
	RegisterDnstapGetFunc(GetterMessageProtocol, GetSocketProtocol, GetSocketProtocolString)
}
