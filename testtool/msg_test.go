package testtool_test

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
	"github.com/mimuret/dnsutils/testtool"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Message", func() {
	Context("GetRandomHostName", func() {
		var (
			name string
		)
		BeforeEach(func() {
			name = testtool.GetRandomHostName()
		})
		It("successful", func() {
			_, ok := dns.IsDomainName(name)
			Expect(ok).To(BeTrue(), "name", name)
			Expect(dnsutils.IsHostname(name)).To(BeTrue(), "name", name)
		})
	})
})

func TestGetRandomHostName(t *testing.T) {
	name := testtool.GetRandomHostName()
	t.Logf("name=%s\n", name)
	_, ok := dns.IsDomainName(name)
	if !ok {
		t.Errorf("not domain name %s", name)
	}
	if ok := dnsutils.IsHostname(name); !ok {
		t.Errorf("not host name %s", name)
	}
}

func FuzzGetRandomHostName(f *testing.F) {
	f.Fuzz(func(t *testing.T, v int64) {
		TestGetRandomHostName(t)
	})
}
