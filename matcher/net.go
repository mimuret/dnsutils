package matcher

import (
	"encoding/json"
	"net"
)

func ParseIPNet(str string) (*IPNet, error) {
	_, ipnet, err := net.ParseCIDR(str)
	if err != nil {
		return nil, err
	}
	return &IPNet{*ipnet}, nil
}

type IPNet struct {
	net.IPNet
}

func (i IPNet) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.String())
}

func (i *IPNet) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "<nil>" {
		i.IPNet = net.IPNet{}
		return nil
	}

	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return err
	}
	i.IPNet = *ipnet
	return nil
}
