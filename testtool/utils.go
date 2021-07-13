package testtool

import (
	"fmt"

	"github.com/miekg/dns"
)

// USE ONLY TEST PACKAGE
func MustNewRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	return rr
}
