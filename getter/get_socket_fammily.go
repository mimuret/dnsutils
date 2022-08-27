package getter

import (
	dnstap "github.com/dnstap/golang-dnstap"
)

const (
	GetterMessageFamily DnstapGetterName = "MessageFamily"
	GetterSocketFamily  DnstapGetterName = "SocketFamily"
)

func GetSocketFamilyString(d *dnstap.Dnstap) string {
	if d == nil {
		return MatchStringUnknown
	}
	msg := d.GetMessage()
	if msg == nil {
		return MatchStringUnknown
	}
	return msg.GetSocketFamily().String()
}

func GetSocketFamily(d *dnstap.Dnstap) interface{} {
	if d == nil {
		return nil
	}
	msg := d.GetMessage()
	if msg == nil {
		return nil
	}
	return msg.GetSocketFamily()
}

func init() {
	RegisterDnstapGetFunc(GetterMessageFamily, GetSocketFamily, GetSocketFamilyString)
	RegisterDnstapGetFunc(GetterSocketFamily, GetSocketFamily, GetSocketFamilyString)
}
