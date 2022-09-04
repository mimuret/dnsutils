package getter_test

import (
	_ "embed"
	"net"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ECSQuery", func() {
	var (
		m *dns.Msg
	)
	BeforeEach(func() {
		m = &dns.Msg{Extra: []dns.RR{
			&dns.OPT{
				Option: []dns.EDNS0{
					&dns.EDNS0_SUBNET{
						Family:        1,
						SourceNetmask: 32,
						SourceScope:   24,
						Address:       net.IPv4(192, 168, 0, 0),
					},
				},
			},
		},
		}
	})
	Context("GetECSQueryString", func() {
		var (
			s       string
			strFunc = getter.NewDnsMsgStrFunc("ECSQuery")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = strFunc(nil)
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("ecs is empty", func() {
			BeforeEach(func() {
				s = strFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid msg", func() {
			BeforeEach(func() {
				s = strFunc(m)
			})
			It("returns qname", func() {
				Expect(s).To(Equal("192.168.0.0/32"))
			})
		})
	})
	Context("GetECSQuery", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnsMsgGetFunc("ECSQuery")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getFunc(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("ecs is empty", func() {
			BeforeEach(func() {
				s = getFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(BeNil())
			})
		})
		When("msg is not nil", func() {
			BeforeEach(func() {
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(&net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 255)}))
			})
		})
	})
	Context("ECSResponseString", func() {
		var (
			s       string
			strFunc = getter.NewDnsMsgStrFunc("ECSResponse")
		)
		When("ecs is empty", func() {
			BeforeEach(func() {
				s = strFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid msg", func() {
			BeforeEach(func() {
				s = strFunc(m)
			})
			It("returns qname", func() {
				Expect(s).To(Equal("192.168.0.0/24"))
			})
		})
	})
	Context("GetECSResponse", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnsMsgGetFunc("ECSResponse")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getFunc(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("ecs is empty", func() {
			BeforeEach(func() {
				s = getFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(BeNil())
			})
		})
		When("msg is not nil", func() {
			BeforeEach(func() {
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(&net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}))
			})
		})
	})
	Context("ECSSourceMaskString", func() {
		var (
			s       string
			strFunc = getter.NewDnsMsgStrFunc("ECSSourceMask")
		)
		When("ecs is empty", func() {
			BeforeEach(func() {
				s = strFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid msg", func() {
			BeforeEach(func() {
				s = strFunc(m)
			})
			It("returns qname", func() {
				Expect(s).To(Equal("32"))
			})
		})
	})
	Context("GetECSSourceMask", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnsMsgGetFunc("ECSSourceMask")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getFunc(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("ecs is empty", func() {
			BeforeEach(func() {
				s = getFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(BeNil())
			})
		})
		When("msg is not nil", func() {
			BeforeEach(func() {
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(uint8(32)))
			})
		})
	})
	Context("ECSScopeMaskString", func() {
		var (
			s       string
			strFunc = getter.NewDnsMsgStrFunc("ECSScopeMask")
		)
		When("ecs is empty", func() {
			BeforeEach(func() {
				s = strFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(Equal(getter.MatchStringUnknown))
			})
		})
		When("valid msg", func() {
			BeforeEach(func() {
				s = strFunc(m)
			})
			It("returns qname", func() {
				Expect(s).To(Equal("24"))
			})
		})
	})
	Context("GetECSScopeMask", func() {
		var (
			s       interface{}
			getFunc = getter.NewDnsMsgGetFunc("ECSScopeMask")
		)
		When("msg is nil", func() {
			BeforeEach(func() {
				s = getFunc(nil)
			})
			It("returns nil", func() {
				Expect(s).To(BeNil())
			})
		})
		When("ecs is empty", func() {
			BeforeEach(func() {
				s = getFunc(&dns.Msg{})
			})
			It("returns unknown", func() {
				Expect(s).To(BeNil())
			})
		})
		When("msg is not nil", func() {
			BeforeEach(func() {
				s = getFunc(m)
			})
			It("returns value", func() {
				Expect(s).To(Equal(uint8(24)))
			})
		})
	})
})
