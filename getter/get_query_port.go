package getter

import (
	"strconv"

	dnstap "github.com/dnstap/golang-dnstap"
)

const (
	GetterQueryPort DnstapGetterName = "QueryPort"
)

func GetQueryPortString(d *dnstap.Dnstap) string {
	if d == nil {
		return MatchStringUnknown
	}
	msg := d.GetMessage()
	if msg == nil {
		return MatchStringUnknown
	}
	return strconv.FormatUint(uint64(msg.GetQueryPort()), 10)
}

func GetQueryPort(d *dnstap.Dnstap) interface{} {
	if d == nil {
		return nil
	}
	msg := d.GetMessage()
	if msg == nil {
		return nil
	}
	return msg.GetQueryPort()
}

func init() {
	RegisterDnstapGetFunc(GetterQueryPort, GetQueryPort, GetQueryPortString)
}
