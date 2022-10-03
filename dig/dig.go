package dig

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

const ContentType = "application/dns-message"

var (
	DefaultResolvers          []string
	ErrPackMsg                = fmt.Errorf("failed to pack request dns message")
	ErrParseTarget            = fmt.Errorf("failed to parse target url")
	ErrCreateRequest          = fmt.Errorf("failed to create http post request")
	ErrRequest                = fmt.Errorf("failed to request")
	ErrUnsupportedContentType = fmt.Errorf("unsupported content type is received")
	ErrReadBody               = fmt.Errorf("failed to read body")
	ErrNotOK                  = fmt.Errorf("status code is not 200")
	ErrParseMsg               = fmt.Errorf("failed to parse DNS message")
)

func init() {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil {
		for _, addr := range cfg.Servers {
			DefaultResolvers = append(DefaultResolvers, addr+":53")
		}
	}
}

type ResolvInterface interface {
	Exchange(*dns.Msg, ...Option) (*dns.Msg, error)
}

var _ ResolvInterface = &Dig{}

type Dig struct {
	Client     *dns.Client
	HTTPClient *http.Client
	Target     string
}

func NewDig() *Dig {
	r := &Dig{
		Client:     &dns.Client{},
		HTTPClient: &http.Client{},
	}
	if len(DefaultResolvers) > 0 {
		r.Target = DefaultResolvers[0]
	}
	return r
}

type Option interface {
	Option(*Dig) error
}

type OptionNet struct {
	Net string
}

func (o *OptionNet) Option(c *Dig) error {
	c.Client.Net = o.Net
	return nil
}

type OptionTarget struct {
	Target string
}

func (o *OptionTarget) Option(c *Dig) error {
	c.Target = o.Target
	return nil
}

type OptionTLSConfig struct {
	TLSConfig *tls.Config
}

func (o *OptionTLSConfig) Option(c *Dig) error {
	c.Client.TLSConfig = o.TLSConfig
	return nil
}

func Simple(name string, qtype uint16, options ...Option) (*dns.Msg, error) {
	m := &dns.Msg{}
	m.SetQuestion(name, qtype)
	return UDP(m, options...)
}

func UDP(m *dns.Msg, options ...Option) (*dns.Msg, error) {
	options = append(options, &OptionNet{Net: "udp"})
	return NewDig().Exchange(m, options...)
}

func TCP(m *dns.Msg, options ...Option) (*dns.Msg, error) {
	options = append(options, &OptionNet{Net: "tcp"})
	return NewDig().Exchange(m, options...)
}

func TLS(m *dns.Msg, options ...Option) (*dns.Msg, error) {
	options = append(options, &OptionNet{Net: "tcp-tls"})
	return NewDig().Exchange(m, options...)
}

func HTTPS(m *dns.Msg, options ...Option) (*dns.Msg, error) {
	options = append(options, &OptionNet{Net: "http-post"})
	return NewDig().Exchange(m, options...)
}

func (d *Dig) Exchange(m *dns.Msg, options ...Option) (*dns.Msg, error) {
	for _, opt := range options {
		opt.Option(d)
	}
	if strings.HasPrefix(d.Client.Net, "http") {
		return d.dialHTTP(m)
	}
	r, _, err := d.Client.Exchange(m, d.Target)
	return r, err
}

func (d *Dig) dialHTTP(m *dns.Msg) (*dns.Msg, error) {
	req, err := d.getRequest(m)
	if err != nil {
		return nil, err
	}
	res, err := d.HTTPClient.Do(req)
	if err != nil {
		return nil, ErrRequest
	}
	defer res.Body.Close()
	if res.Header.Get("Content-Type") != ContentType {
		return nil, ErrUnsupportedContentType
	}
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, ErrReadBody
	}
	if res.StatusCode != 200 {
		return nil, ErrNotOK
	}
	r := &dns.Msg{}
	if err := r.Unpack(raw); err != nil {
		return nil, ErrParseMsg
	}
	return r, nil
}

func (d *Dig) getRequest(m *dns.Msg) (*http.Request, error) {
	var (
		req *http.Request
	)
	raw, err := m.Pack()
	if err != nil {
		return nil, ErrPackMsg
	}
	url, err := url.Parse(d.Target)
	if err != nil {
		return nil, ErrParseTarget
	}
	if d.Client.Net == "http-get" {
		dnsb64param := base64.RawURLEncoding.EncodeToString(raw)
		q := url.Query()
		q.Set("dns", dnsb64param)
		url.RawQuery = q.Encode()
		req, err = http.NewRequest(http.MethodGet, url.String(), nil)
		if err != nil {
			return nil, ErrCreateRequest
		}
	} else {
		req, err = http.NewRequest(http.MethodPost, url.String(), bytes.NewReader(raw))
		if err != nil {
			return nil, ErrCreateRequest
		}
		req.Header.Add("content-type", ContentType)
	}
	return req, nil
}
