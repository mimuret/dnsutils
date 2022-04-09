package transfer_test

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
	"github.com/mimuret/dnsutils/testtool"
	"github.com/mimuret/dnsutils/transfer"

	. "github.com/onsi/ginkgo"

	. "github.com/onsi/gomega"
)

//go:embed testdata/example.jp.normal
var testZoneNormal []byte

//go:embed testdata/example.jp.big
var testZoneBig []byte

func TestDNSUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "transfer Suite")
}

var _ = Describe("transfer", func() {
	var (
		err       error
		w         *testtool.ResponseWriter
		tr        *transfer.Transfer
		req       *dns.Msg
		invalidRR = &dns.TXT{Txt: []string{"HU5kaaBpGPOuppdaeNMB1psCevj1prYuhDrZHI1svCWZbSfpqEkFWRMAzeclAU90eOcBu9tPkjVIKXJYupMoR4Rq9jSOgAWmAgIwsgR2vq5sF6whn59BnFm908ZekZC6ZnfZylaYhVTMwXcScK2Az3ndIc2Vr3oFHG1ixl3hzzZNsjflomd86vqUdwNWfsTYC2CDEFv43fEFb6ECUbIPzlDFNziemMwi50LZQ6B7Edu3cED8psRfLbyCd3eU4EdCBX999EAaOWw1ulVJwB4WRiTMaL2g2NJ3SNitV7EKUJMCH0PVtQErNMLWlUZgsi2oQszZAslisbT3g3VyviXU90j9Tp97IYCfQioBDmLVsQeFKnL2JsdIy5Vnyt4n7j4XHc0FlJltZCInvt8xlTDQURmdVzKycyRr5TnFjW3pdNOrOZN9bc9LmykUfAA1RTTbvQa5TULpbFqb1roI9ZhYTuP4fswvXuH5u0BpViaGzjEPTdPxDxInQJsp21hzjn"}}
		z         *dnsutils.Zone
	)
	BeforeEach(func() {
		w = &testtool.ResponseWriter{}
		tr = transfer.NewTransfer(nil)
		req = &dns.Msg{}
		req.SetAxfr("example.jp.")
		testZoneNormalBuf := bytes.NewBuffer(testZoneNormal)
		z = &dnsutils.Zone{}
		Expect(z.Read(testZoneNormalBuf)).To(Succeed())
	})
	Context("Transfer", func() {
		Context("Start/Finish", func() {
			BeforeEach(func() {
				tr.Start(w, req)
				err = tr.Finish()
			})
			It("successfull", func() {
				Expect(err).To(Succeed())
			})
		})
		Context("SendRR", func() {
			When("valid RR", func() {
				BeforeEach(func() {
					tr.Start(w, req)
					z.GetRootNode().IterateNameNode(func(nni dnsutils.NameNodeInterface) error {
						return nni.IterateNameRRSet(func(ri dnsutils.RRSetInterface) error {
							tr.SendRR(ri.GetRRs())
							return nil
						})
					})
					err = tr.Finish()
				})
				It("successfull", func() {
					Expect(err).To(Succeed())
				})
			})
			When("invalid RR", func() {
				BeforeEach(func() {
					tr.Start(w, req)
					tr.SendRR([]dns.RR{invalidRR})
					err = tr.Finish()
				})
				It("retrns err", func() {
					Expect(err).To(HaveOccurred())
				})
			})
			When("write error", func() {
				BeforeEach(func() {
					w.ErrWriteMsg = fmt.Errorf("failed")
					tr.Start(w, req)
					z.GetRootNode().IterateNameNode(func(nni dnsutils.NameNodeInterface) error {
						return nni.IterateNameRRSet(func(ri dnsutils.RRSetInterface) error {
							tr.SendRR(ri.GetRRs())
							return nil
						})
					})
					err = tr.Finish()
				})
				It("retrns err", func() {
					Expect(err).To(HaveOccurred())
				})
			})
		})
	})
	Context("TransferZone", func() {
		BeforeEach(func() {
			err = transfer.TransferZone(z, w, req, nil)
		})
		It("succeed", func() {
			Expect(err).To(Succeed())
		})
	})
	Context("OutRR", func() {
		var (
			evs []*dns.Envelope
		)
		BeforeEach(func() {
			evs = nil
		})
		When("msg size is less than 16k", func() {
			BeforeEach(func() {
				evCh := make(chan *dns.Envelope, 128)
				chRRs := make(chan []dns.RR, 128)
				wg := &sync.WaitGroup{}
				wg.Add(1)
				go func() {
					err = transfer.OutRR(req, chRRs, evCh)
					wg.Done()
				}()
				testZoneNormalBuf := bytes.NewBuffer(testZoneNormal)
				z := &dnsutils.Zone{}
				Expect(z.Read(testZoneNormalBuf)).To(Succeed())
				z.GetRootNode().IterateNameNode(func(nni dnsutils.NameNodeInterface) error {
					return nni.IterateNameRRSet(func(ri dnsutils.RRSetInterface) error {
						chRRs <- ri.GetRRs()
						return nil
					})
				})
				close(chRRs)
				wg.Wait()
				close(evCh)
				for ev := range evCh {
					evs = append(evs, ev)
				}
			})
			It("no error", func() {
				Expect(err).To(Succeed())
			})
			It("returns 1 msg", func() {
				Expect(len(evs)).To(Equal(1))
			})
		})
		When("msg size is grater than 16k", func() {
			BeforeEach(func() {
				evCh := make(chan *dns.Envelope, 128)
				chRRs := make(chan []dns.RR, 128)
				wg := &sync.WaitGroup{}
				wg.Add(1)
				go func() {
					err = transfer.OutRR(req, chRRs, evCh)
					wg.Done()
				}()
				testZoneNormalBuf := bytes.NewBuffer(testZoneBig)
				z := &dnsutils.Zone{}
				Expect(z.Read(testZoneNormalBuf)).To(Succeed())
				z.GetRootNode().IterateNameNode(func(nni dnsutils.NameNodeInterface) error {
					return nni.IterateNameRRSet(func(ri dnsutils.RRSetInterface) error {
						chRRs <- ri.GetRRs()
						return nil
					})
				})
				close(chRRs)
				wg.Wait()
				close(evCh)
				for ev := range evCh {
					evs = append(evs, ev)
				}
			})
			It("no error", func() {
				Expect(err).To(Succeed())
			})
			It("returns 6 msg", func() {
				Expect(len(evs)).To(Equal(6))
				Expect(evs[0].RR[0].Header().Name).To(Equal("example.jp."))
				Expect(evs[0].RR[len(evs[0].RR)-1].Header().Name).To(Equal("zzz1.example.jp."))
				Expect(evs[1].RR[0].Header().Name).To(Equal("zzz2.example.jp."))
				Expect(evs[2].RR[0].Header().Name).To(Equal("zzz3.example.jp."))
				Expect(evs[3].RR[0].Header().Name).To(Equal("zzz4.example.jp."))
				Expect(evs[4].RR[0].Header().Name).To(Equal("zzz5.example.jp."))
				Expect(evs[5].RR[0].Header().Name).To(Equal("zzz6.example.jp."))
			})
		})
		When("failed to pack RR", func() {
			BeforeEach(func() {
				evCh := make(chan *dns.Envelope, 128)
				chRRs := make(chan []dns.RR, 128)
				wg := &sync.WaitGroup{}
				wg.Add(1)
				go func() {
					err = transfer.OutRR(req, chRRs, evCh)
					wg.Done()
				}()
				// long string
				chRRs <- []dns.RR{invalidRR}
				close(chRRs)
				wg.Wait()
				close(evCh)
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
