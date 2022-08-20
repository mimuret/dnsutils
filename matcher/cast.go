package matcher

import (
	"fmt"
	"net"
)

func GetIPNet(arg interface{}) (*net.IPNet, error) {
	switch v := arg.(type) {
	case net.IPNet:
		return &v, nil
	case *net.IPNet:
		return v, nil
	case string:
		_, ipNet, err := net.ParseCIDR(v)
		if err != nil {
			return nil, fmt.Errorf("invalid format: %w", err)
		}
		return ipNet, nil
	}
	return nil, fmt.Errorf("invalid type %v", arg)
}
