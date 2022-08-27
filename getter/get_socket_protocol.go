package getter

import (
	dnstap "github.com/dnstap/golang-dnstap"
)

const (
	GetterMessageType DnstapGetterName = "MessageType"
)

func GetMessageTypeString(d *dnstap.Dnstap) string {
	if d == nil {
		return MatchStringUnknown
	}
	msg := d.GetMessage()
	if msg == nil {
		return MatchStringUnknown
	}
	return msg.GetType().String()
}

func GetMessageType(d *dnstap.Dnstap) interface{} {
	if d == nil {
		return nil
	}
	msg := d.GetMessage()
	if msg == nil {
		return nil
	}
	return msg.GetType()
}

func init() {
	RegisterDnstapGetFunc(GetterMessageType, GetMessageType, GetMessageTypeString)
}
