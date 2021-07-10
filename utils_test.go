package dnsutils_test

import (
	"github.com/miekg/dns"

	"github.com/mimuret/dnsutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func MustNewRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

var _ = Describe("utils", func() {
	Context("Test for Equals", func() {
		It("can compare between non-normalized name", func() {
			testcases := []struct {
				A   string
				B   string
				res OmegaMatcher
			}{
				{
					"example.jp.", "example.jp.", BeTrue(),
				},
				{
					"example.jp.", "example.jp", BeTrue(),
				},
				{
					"Example.jp.", "example.Jp", BeTrue(),
				},
				{
					"Example.j2p.", "example.Jp", BeFalse(),
				},
				{
					".example.jp.", "example.jp.", BeFalse(),
				},
				{
					"jp.", "example.jp.", BeFalse(),
				},
				{
					"example.jp.", "jp.", BeFalse(),
				},
			}
			for _, tc := range testcases {
				res := dnsutils.Equals(tc.A, tc.B)
				Expect(res).To(tc.res)
			}

		})
	})
})
