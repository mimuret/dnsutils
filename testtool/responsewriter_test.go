package testtool_test

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/testtool"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("testtool", func() {
	Context("ResponseWriter", func() {
		var (
			err  error
			w    *testtool.ResponseWriter
			addr net.Addr
			q    *dns.Msg
			bs   []byte
			l    int
		)
		BeforeEach(func() {
			var err error
			w = &testtool.ResponseWriter{}
			q = &dns.Msg{}
			q.SetQuestion("example.jp.", dns.TypeSOA)
			bs, err = q.Pack()
			Expect(err).To(Succeed())
		})
		Context("LocalAddr", func() {
			When("LocalAddress doesn't exists", func() {
				BeforeEach(func() {
					addr = w.LocalAddr()
				})
				It("returns 127.0.0.1:53", func() {
					Expect(addr.Network()).To(Equal("udp"))
					Expect(addr.String()).To(Equal("127.0.0.1:53"))
				})
			})
			When("LocalAddress exists", func() {
				BeforeEach(func() {
					w.LocalAddress = &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: 53}
					addr = w.LocalAddr()
				})
				It("returns LocalAddress", func() {
					Expect(addr.Network()).To(Equal("tcp"))
					Expect(addr.String()).To(Equal("127.0.0.2:53"))
				})
			})
		})
		Context("RemoteAddr", func() {
			When("RemoteAddress doesn't exists", func() {
				BeforeEach(func() {
					addr = w.RemoteAddr()
				})
				It("returns 10.0.0.1:38000", func() {
					Expect(addr.Network()).To(Equal("udp"))
					Expect(addr.String()).To(Equal("10.0.0.1:38000"))
				})
			})
			When("LocalAddress exists", func() {
				BeforeEach(func() {
					w.RemoteAddress = &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 38001}
					addr = w.RemoteAddr()
				})
				It("returns RemoteAddress", func() {
					Expect(addr.Network()).To(Equal("tcp"))
					Expect(addr.String()).To(Equal("10.0.0.2:38001"))
				})
			})
		})
		Context("WriteMsg", func() {
			When("ErrWriteMsg doesn't exist", func() {
				BeforeEach(func() {
					err = w.WriteMsg(q)
				})
				It("successful", func() {
					Expect(err).To(Succeed())
					Expect(w.Msg).NotTo(BeNil())
					Expect(w.Msg).To(Equal(q))
				})
			})
			When("ErrWriteMsg exists", func() {
				BeforeEach(func() {
					w.ErrWriteMsg = fmt.Errorf("error")
					err = w.WriteMsg(q)
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
		Context("Write", func() {
			When("ErrWrite doesn't exist", func() {
				BeforeEach(func() {
					l, err = w.Write(bs)
				})
				It("successful", func() {
					Expect(err).To(Succeed())
					Expect(l).To(Equal(len(bs)))
				})
			})
			When("ErrWrite exists", func() {
				BeforeEach(func() {
					w.ErrWrite = fmt.Errorf("error")
					l, err = w.Write(bs)
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
					Expect(l).To(Equal(0))
				})
			})
		})
		Context("Close", func() {
			When("ErrClose doesn't exist", func() {
				BeforeEach(func() {
					err = w.Close()
				})
				It("successful", func() {
					Expect(err).To(Succeed())
				})
			})
			When("ErrClose exists", func() {
				BeforeEach(func() {
					w.ErrClose = fmt.Errorf("error close")
					err = w.Close()
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
					Expect(err).To(Equal(w.ErrClose))
				})
			})
		})
		Context("TsigStatus", func() {
			When("ErrTsigStatus doesn't exist", func() {
				BeforeEach(func() {
					err = w.TsigStatus()
				})
				It("successful", func() {
					Expect(err).To(Succeed())
				})
			})
			When("ErrWrite exists", func() {
				BeforeEach(func() {
					w.ErrTsigStatus = fmt.Errorf("error TsigStatus")
					err = w.TsigStatus()
				})
				It("returns error", func() {
					Expect(err).To(HaveOccurred())
					Expect(err).To(Equal(w.ErrTsigStatus))
				})
			})
		})
	})
})
