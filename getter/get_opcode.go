package getter

import (
	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
)

const (
	GetterOpcode DnsMsgGetterName = "Opcode"
)

func GetOpcodeString(d *dns.Msg) string {
	if d == nil {
		return MatchStringUnknown
	}
	return dnsutils.ConvertNumberToString(dns.OpcodeToString, "OPCODE", d.Opcode)
}

func GetOpcode(d *dns.Msg) interface{} {
	if d == nil {
		return nil
	}
	return d.Opcode
}

func init() {
	RegisterDnsMsgGetFunc(GetterOpcode, GetOpcode, GetOpcodeString)
}
