package getter

import (
	"strconv"

	dnstap "github.com/dnstap/golang-dnstap"
)

const (
	GetterResponsePort DnstapGetterName = "ResponsePort"
)

func GetResponsePortString(d *dnstap.Dnstap) string {
	if d == nil {
		return MatchStringUnknown
	}
	msg := d.GetMessage()
	if msg == nil {
		return MatchStringUnknown
	}
	return strconv.FormatUint(uint64(msg.GetResponsePort()), 10)
}

func GetResponsePort(d *dnstap.Dnstap) interface{} {
	if d == nil {
		return nil
	}
	msg := d.GetMessage()
	if msg == nil {
		return nil
	}
	return msg.GetResponsePort()
}

func init() {
	RegisterDnstapGetFunc(GetterResponsePort, GetResponsePort, GetResponsePortString)
}
