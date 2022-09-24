package dig_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"math/big"
	"time"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsutils/dig"
	"github.com/mimuret/dnsutils/testtool"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type handler struct {
	RR dns.RR
}

func (m *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	res := new(dns.Msg)
	res.SetReply(r)
	res.Answer = []dns.RR{m.RR}
	w.WriteMsg(res)
}

var _ = Describe("dig package", func() {
	var (
		msg            *dns.Msg
		err            error
		svc            *dns.Server
		startCh, endCh chan struct{}
		m              *dns.Msg
		opts           []dig.Options
	)
	BeforeEach(func() {
		startCh = make(chan struct{})
		endCh = make(chan struct{})
		h := &handler{RR: testtool.MustNewRR("www.example.jp. IN 300 A 192.168.0.1")}
		svc = &dns.Server{Addr: "127.0.0.1:20053", Net: "udp", Handler: h, NotifyStartedFunc: func() { close(startCh) }}
		opts = []dig.Options{&dig.OptionTarget{Target: "127.0.0.1:20053"}}
		m = new(dns.Msg)
		m.SetQuestion("www.example.jp.", dns.TypeA)
	})
	Context("Simple", func() {
		BeforeEach(func() {
			msg, err = dig.Simple("m.root-servers.net.", dns.TypeA)
		})
		It("returns msg", func() {
			Expect(err).To(Succeed())
			Expect(msg.Rcode).To(Equal(dns.RcodeSuccess))
		})
	})
	Context("UDP", func() {
		BeforeEach(func() {
			go func() {
				err := svc.ListenAndServe()
				if err != nil {
					panic(err)
				}
				close(endCh)
			}()
			<-startCh
			msg, err = dig.UDP(m, opts...)
			svc.Shutdown()
			<-endCh
		})
		It("returns msg", func() {
			Expect(err).To(Succeed())
			Expect(msg.Rcode).To(Equal(dns.RcodeSuccess))
		})
	})
	Context("TCP", func() {
		BeforeEach(func() {
			svc.Net = "tcp"
			go func() {
				err := svc.ListenAndServe()
				if err != nil {
					panic(err)
				}
				close(endCh)
			}()
			<-startCh
			msg, err = dig.TCP(m, opts...)
			svc.Shutdown()
			<-endCh
		})
		It("returns msg", func() {
			Expect(err).To(Succeed())
			Expect(msg.Rcode).To(Equal(dns.RcodeSuccess))
		})
	})
	Context("TLS", func() {
		BeforeEach(func() {
			var (
				cert []byte
				priv crypto.PrivateKey
			)
			cert, priv, err = generateTLS()
			Expect(err).To(Succeed())
			svc.Net = "tcp-tls"
			pool := x509.NewCertPool()
			pool.AddCert(&x509.Certificate{Raw: cert})
			svc.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{cert},
						PrivateKey:  priv,
					},
				},
				RootCAs: pool,
			}
			go func() {
				err := svc.ListenAndServe()
				if err != nil {
					panic(err)
				}
				close(endCh)
			}()
			<-startCh
			opts = append(opts, &dig.OptionTLSConfig{TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
			}})
			msg, err = dig.TLS(m, opts...)
			svc.Shutdown()
			<-endCh
		})
		It("returns msg", func() {
			Expect(err).To(Succeed())
			Expect(msg.Rcode).To(Equal(dns.RcodeSuccess))
		})
	})
	Context("HTTP", func() {
		BeforeEach(func() {
			opts = []dig.Options{&dig.OptionTarget{Target: "https://public.dns.iij.jp/dns-query"}}
			msg, err = dig.HTTPS(m, opts...)
		})
		It("returns msg", func() {
			Expect(err).To(Succeed())
			Expect(msg.Rcode).To(Equal(dns.RcodeNameError))
		})
	})
	Context("Dig", func() {
		var (
			d   *dig.Dig
			req *dns.Msg
			res *dns.Msg
		)
		BeforeEach(func() {
			req = new(dns.Msg)
			req.SetQuestion("www.example.jp.", dns.TypeA)
			d = dig.NewDig()
		})
		Context("Exchange", func() {
			When("http-get", func() {
				BeforeEach(func() {
					d.Client.Net = "http-get"
				})
				When("valid server", func() {
					BeforeEach(func() {
						res, err = d.Exchange(req, &dig.OptionTarget{Target: "https://public.dns.iij.jp/dns-query"})
					})
					It("returns msg", func() {
						Expect(err).To(Succeed())
						Expect(res.Rcode).To(Equal(dns.RcodeNameError))
					})
				})
				When("invalid path", func() {
					BeforeEach(func() {
						res, err = d.Exchange(req, &dig.OptionTarget{Target: "https://public.dns.iij.jp/"})
					})
					It("returns msg", func() {
						Expect(err).To(HaveOccurred())
						Expect(err).To(MatchError(dig.ErrUnsupportedContentType))
					})
				})
				When("invalid server", func() {
					BeforeEach(func() {
						res, err = d.Exchange(req, &dig.OptionTarget{Target: "https://example.jp/dns-query"})
					})
					It("returns msg", func() {
						Expect(err).To(HaveOccurred())
						Expect(err).To(MatchError(dig.ErrRequest))
					})
				})
			})
		})
	})
})

func generateTLS() ([]byte, crypto.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}
