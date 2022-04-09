package testtool

import (
	"net"

	"github.com/miekg/dns"
)

var _ dns.ResponseWriter = &ResponseWriter{}

type ResponseWriter struct {
	LocalAddress  net.Addr
	RemoteAddress net.Addr

	Msg      *dns.Msg
	Msgs     []*dns.Msg
	MsgBytes []byte

	ErrWriteMsg   error
	ErrWrite      error
	ErrClose      error
	ErrTsigStatus error
}

// LocalAddr returns the net.Addr of the server
func (w *ResponseWriter) LocalAddr() net.Addr {
	if w.LocalAddress != nil {
		return w.LocalAddress
	}
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

// RemoteAddr returns the net.Addr of the client that sent the current request.
func (w *ResponseWriter) RemoteAddr() net.Addr {
	if w.RemoteAddress != nil {
		return w.RemoteAddress
	}
	return &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 38000}
}

// WriteMsg writes a reply back to the client.
func (w *ResponseWriter) WriteMsg(msg *dns.Msg) error {
	if w.ErrWriteMsg != nil {
		return w.ErrWriteMsg
	}
	w.Msg = msg
	w.Msgs = append(w.Msgs, msg)
	return nil
}

// Write writes a raw buffer back to the client.
func (w *ResponseWriter) Write(bs []byte) (int, error) {
	if w.ErrWrite != nil {
		return 0, w.ErrWrite
	}
	w.MsgBytes = bs
	return len(bs), nil
}

// Close closes the connection.
func (w *ResponseWriter) Close() error {
	return w.ErrClose
}

// TsigStatus returns the status of the Tsig.
func (w *ResponseWriter) TsigStatus() error {
	return w.ErrTsigStatus
}

// TsigTimersOnly sets the tsig timers only boolean.
func (w *ResponseWriter) TsigTimersOnly(bool) {

}

// Hijack lets the caller take over the connection.
// After a call to Hijack(), the DNS package will not do anything with the connection.
func (w *ResponseWriter) Hijack() {

}
