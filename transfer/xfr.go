package transfer

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils"
)

// DNSHeaderSize is DNS message header size
const DNSHeaderSize = 6

// TransferLimitSize uses for split AXFR DNS Message.
const TransferLimitSize = 16383

// Transfer is utils struct for outbound xfr.
type Transfer struct {
	EvSize int
	tr     *dns.Transfer
	chRRs  chan []dns.RR
	evCh   chan *dns.Envelope

	errTr    error
	errOutRR error

	wgTROut *sync.WaitGroup
	wgOutRR *sync.WaitGroup
}

// NewTransfer creates Transfer
func NewTransfer(tr *dns.Transfer) *Transfer {
	if tr == nil {
		tr = &dns.Transfer{}
	}
	return &Transfer{tr: tr, EvSize: 8}
}

// Start is the start transfer process.
func (t *Transfer) Start(w dns.ResponseWriter, q *dns.Msg) {
	t.evCh = make(chan *dns.Envelope, t.EvSize)

	t.wgTROut = &sync.WaitGroup{}
	t.wgTROut.Add(1)
	go func() {
		if err := t.tr.Out(w, q, t.evCh); err != nil {
			t.errTr = err
		}
		t.wgTROut.Done()
	}()

	t.wgOutRR = &sync.WaitGroup{}
	t.chRRs = make(chan []dns.RR, 1)
	t.wgOutRR.Add(1)
	go func() {
		if err := OutRR(q, t.chRRs, t.evCh); err != nil {
			t.errOutRR = err
		}
		t.wgOutRR.Done()
	}()
}

// SendRR is transfer RR slice.
func (t *Transfer) SendRR(rrs []dns.RR) {
	t.chRRs <- rrs
}

// Finish is the end transfer process.
func (t *Transfer) Finish() error {
	// finish OutRR Loop
	close(t.chRRs)
	// OutRR is finished
	t.wgOutRR.Wait()

	// finish Out Loop
	close(t.evCh)
	// tr.Out is finished
	t.wgTROut.Wait()

	if t.errOutRR != nil {
		return t.errOutRR
	}
	return t.errTr
}

// TransferZone transers dnsutils.ZoneInterface
func TransferZone(z dnsutils.ZoneInterface, w dns.ResponseWriter, q *dns.Msg, tr *dns.Transfer) error {
	var soa []dns.RR
	t := NewTransfer(tr)
	t.Start(w, q)
	z.GetRootNode().IterateNameNode(func(nni dnsutils.NameNodeInterface) error {
		return nni.IterateNameRRSet(func(ri dnsutils.RRSetInterface) error {
			if ri.GetRRtype() == dns.TypeSOA {
				soa = ri.GetRRs()
			}
			t.SendRR(ri.GetRRs())
			return nil
		})
	})
	t.SendRR(soa)
	return t.Finish()
}

// OutRR makes and sends dns.Envelope considering the message size.
func OutRR(req *dns.Msg, chRRs chan []dns.RR, evCh chan *dns.Envelope) error {
	var (
		msgLen    int
		m         *dns.Msg
		envelopRR []dns.RR
		i         int
	)
	m = &dns.Msg{}
	m.SetReply(req)
	for rrs := range chRRs {
		for _, rr := range rrs {
			m.Answer = []dns.RR{rr}
			bs, err := m.Pack()
			rrLen := len(bs) - DNSHeaderSize
			if err != nil {
				return fmt.Errorf("failed to pack RR on OutRR: %w", err)
			}
			if msgLen+rrLen > TransferLimitSize {
				m.Answer = append(envelopRR, rr)
				mbs, err := m.Pack()
				if err != nil {
					return fmt.Errorf("failed to pack Msg on OutRR: %w", err)
				}
				if len(mbs) > dns.MaxMsgSize {
					evCh <- &dns.Envelope{
						RR: envelopRR,
					}
					envelopRR = []dns.RR{rr}
					msgLen = rrLen
					i++
				} else {
					evCh <- &dns.Envelope{
						RR: m.Answer,
					}
					envelopRR = []dns.RR{}
					msgLen = 0
					i++
				}
			} else {
				msgLen += rrLen
				envelopRR = append(envelopRR, rr)
			}
		}
	}
	if len(envelopRR) > 0 {
		evCh <- &dns.Envelope{
			RR: envelopRR,
		}
	}
	return nil
}
