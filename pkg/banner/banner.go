// Package banner reads what a service says when something connects to it.
//
// A scan says a port is open, which is the smaller half of the question. "3306 is open" is a fact
// nobody can act on; "3306 is MariaDB 10.6, answering the internet" is a finding. The difference is
// a banner, and getting one costs a read on a connection the scan has already made.
//
// Three things are tried, in the order that costs least:
//
//   - A read. Most services worth naming greet whoever connects -- SSH, SMTP, FTP, POP3, IMAP,
//     MySQL and the rest all say who they are before they are asked.
//   - An HTTP request, for the ones that say nothing until spoken to. A web server is silent on
//     connect and identifies itself readily in a response header.
//   - A TLS handshake, which is tried first on the ports that conventionally speak TLS and last on
//     the ports that do not. It names the service and hands over the certificate with it.
//
// Nothing here trusts what it reads. A banner is arbitrary bytes from a stranger that end up in a
// database and a report, so the text rendering strips them down to printable characters, and the
// TLS handshake does not verify the certificate -- it is being read, not relied on.
package banner

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"

	"github.com/altshiftab/port_scanner/pkg/banner/banner_config"
)

// userAgent is what the HTTP probe calls itself. A scanner that identifies itself is one an
// operator reading their own logs can account for, which is worth more than the little that hiding
// would buy.
const userAgent = "port_scanner/1.0"

// Tls is what a TLS handshake revealed about the service behind a port.
type Tls struct {
	Version            string `json:"version,omitzero"`
	CipherSuite        string `json:"cipher_suite,omitzero"`
	NegotiatedProtocol string `json:"negotiated_protocol,omitzero"`

	// The leaf certificate, which is the part of a handshake worth keeping: it names who the
	// service claims to be, and a name that does not match the address it was found at is often the
	// first sign of what a host actually is.
	Subject   string    `json:"subject,omitzero"`
	Issuer    string    `json:"issuer,omitzero"`
	DnsNames  []string  `json:"dns_names,omitzero"`
	NotBefore time.Time `json:"not_before,omitzero"`
	NotAfter  time.Time `json:"not_after,omitzero"`
}

// Banner is what a service said about itself.
type Banner struct {
	// Raw is what the service sent, truncated to the configured length. It is kept beside the text
	// rendering because a binary protocol's greeting does not survive being made printable, and it
	// is the only evidence of what was actually on the wire.
	Raw []byte `json:"raw,omitzero"`

	// Text is Raw rendered as one line of printable characters.
	Text string `json:"text,omitzero"`

	// Service is what the banner identifies, or -- where it identified nothing -- what
	// conventionally listens on the port. It is a guess in the second case and the caller cannot
	// tell which case it is from this field alone; a Raw of any length means it was read rather
	// than assumed.
	Service string `json:"service,omitzero"`

	// Tls is the handshake, where the port spoke TLS.
	Tls *Tls `json:"tls,omitzero"`
}

// newBanner assembles what was read into a banner, naming the service from it.
func newBanner(raw []byte, port int, tlsDetails *Tls) *Banner {
	return &Banner{
		Raw:     raw,
		Text:    text(raw),
		Service: identify(port, raw, tlsDetails),
		Tls:     tlsDetails,
	}
}

// Grab reads what the service on an already-open connection says about itself.
//
// The connection is consumed: bytes are read from it and a probe may be written to it, so the
// caller should do nothing with it afterwards but close it. It is not closed here -- it belongs to
// the caller, who opened it.
//
// A port that said nothing and could not be made to speak returns nil rather than an empty banner:
// a port that is open and silent is a real answer, and it is not the same as one that named itself.
//
// TLS on a port that does not conventionally speak it cannot be tried here, because a handshake
// needs a connection nothing has been written to yet. GrabAddress does that, at the cost of a
// second connection.
func Grab(ctx context.Context, connection net.Conn, port int, options ...banner_config.Option) *Banner {
	if connection == nil {
		return nil
	}

	return grab(ctx, connection, port, banner_config.New(options...))
}

func grab(ctx context.Context, connection net.Conn, port int, config *banner_config.Config) *Banner {
	if config.Tls && isTlsPort(port) {
		return grabTls(ctx, connection, port, config)
	}

	if raw := read(ctx, connection, config, config.Timeout); len(raw) > 0 {
		return newBanner(raw, port, nil)
	}

	// The port is open and has said nothing, which is what a web server does. Nothing has been
	// written to the connection yet, so it is still good for a probe.
	if config.Http {
		if raw := probeHttp(ctx, connection, config); len(raw) > 0 {
			return newBanner(raw, port, nil)
		}
	}

	return nil
}

// GrabTls performs a TLS handshake on an already-open connection and reads what it reveals.
//
// It must be given a connection nothing has been written to or read from, since a handshake has to
// be the first thing on the wire.
func GrabTls(ctx context.Context, connection net.Conn, port int, options ...banner_config.Option) *Banner {
	if connection == nil {
		return nil
	}

	return grabTls(ctx, connection, port, banner_config.New(options...))
}

func grabTls(ctx context.Context, connection net.Conn, port int, config *banner_config.Config) *Banner {
	serverName := config.ServerName
	if serverName == "" {
		// A handshake addressed to a bare address sends no SNI, which is what a client with only an
		// address would do. Sending the address as a name instead is rejected outright by some
		// servers, so it is left off.
		if host, _, err := net.SplitHostPort(remoteAddress(connection)); err == nil {
			if net.ParseIP(host) == nil {
				serverName = host
			}
		}
	}

	deadline := time.Now().Add(config.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil
	}

	tlsConnection := tls.Client(connection, &tls.Config{
		// The certificate is being read, not relied on. A scan that refused to look at an expired
		// or self-signed certificate would be blind to exactly the hosts worth reporting.
		InsecureSkipVerify: true, //nolint:gosec // G402: the certificate is evidence, not a trust decision.
		ServerName:         serverName,
		// Both, because a scan meets old servers. The floor is the library's.
		MinVersion: tls.VersionTLS10,
	})

	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return nil
	}

	tlsDetails := describeTls(tlsConnection.ConnectionState())

	// The handshake named the service. Asking it for a response names the software as well, which
	// is the difference between "https" and "https, nginx 1.18".
	var raw []byte
	if config.Http {
		raw = probeHttp(ctx, tlsConnection, config)
	}

	return newBanner(raw, port, tlsDetails)
}

// GrabAddress dials the address and reads what the service there says about itself.
//
// It is the whole of a grab for a caller with no connection in hand: a SYN scan, which never opens
// one, or anything asking about a single port. A caller that already has an open connection should
// use Grab instead and save the dial.
//
// Where the plain read and the HTTP probe both come up empty and the port is not one that
// conventionally speaks TLS, a second connection is made to try a handshake on it. That is the one
// case a grab costs two connections, and it is what finds TLS on a port nobody expected it on.
func GrabAddress(ctx context.Context, host string, port int, options ...banner_config.Option) *Banner {
	if host == "" {
		return nil
	}

	config := banner_config.New(options...)
	address := net.JoinHostPort(host, strconv.Itoa(port))

	connection, err := dial(ctx, address, config)
	if err != nil {
		return nil
	}

	grabbed := grab(ctx, connection, port, config)
	_ = connection.Close()

	if grabbed != nil || !config.Tls || isTlsPort(port) {
		return grabbed
	}

	// Silent in the clear. It may be speaking TLS on a port that has no name for it, which a
	// handshake settles -- but only on a connection nothing has been written to.
	tlsConnection, err := dial(ctx, address, config)
	if err != nil {
		return nil
	}
	defer func() { _ = tlsConnection.Close() }()

	return grabTls(ctx, tlsConnection, port, config)
}

func dial(ctx context.Context, address string, config *banner_config.Config) (net.Conn, error) {
	dialContext, cancel := context.WithTimeout(ctx, config.DialTimeout)
	defer cancel()

	var dialer net.Dialer
	connection, err := dialer.DialContext(dialContext, "tcp", address)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("dialer dial context: %w", err), address)
	}

	return connection, nil
}

// read collects what the service sends, up to the configured length.
//
// The first read waits the full timeout, because that is the wait for the service to decide to say
// anything at all. The reads after it wait only the settle timeout: a banner arrives in one segment
// or a few in quick succession, and once the first has come the rest is not worth waiting seconds
// for.
func read(
	ctx context.Context,
	connection net.Conn,
	config *banner_config.Config,
	firstTimeout time.Duration,
) []byte {
	buffer := make([]byte, 0, min(config.Length, 2048))
	chunk := make([]byte, 2048)
	timeout := firstTimeout

	for len(buffer) < config.Length {
		if ctx.Err() != nil {
			break
		}

		deadline := time.Now().Add(timeout)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err := connection.SetReadDeadline(deadline); err != nil {
			break
		}

		count, err := connection.Read(chunk[:min(len(chunk), config.Length-len(buffer))])
		if count > 0 {
			buffer = append(buffer, chunk[:count]...)
		}
		if err != nil {
			break
		}

		timeout = config.SettleTimeout
	}

	return buffer
}

// probeHttp asks a silent port for a web page and returns what comes back.
//
// HTTP/1.0 with an explicit close, rather than 1.1: the response is wanted whole and then the
// connection is finished with, and 1.0 says so without a Connection header having to be trusted.
func probeHttp(ctx context.Context, connection net.Conn, config *banner_config.Config) []byte {
	host := config.ServerName
	if host == "" {
		host = remoteAddress(connection)
	}

	request := "GET / HTTP/1.0\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: " + userAgent + "\r\n" +
		"Accept: */*\r\n" +
		"\r\n"

	deadline := time.Now().Add(config.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetWriteDeadline(deadline); err != nil {
		return nil
	}

	if _, err := connection.Write([]byte(request)); err != nil {
		return nil
	}

	return read(ctx, connection, config, config.Timeout)
}

// remoteAddress is the connection's far end as a string, or empty where it has none.
//
// A net.Conn is an interface anyone may implement, and the standard library's own returns a nil
// address for a connection that has been closed, so the address cannot simply be dereferenced.
func remoteAddress(connection net.Conn) string {
	if connection == nil {
		return ""
	}

	address := connection.RemoteAddr()
	if address == nil {
		return ""
	}

	return address.String()
}

// describeTls reads the parts of a handshake worth keeping.
func describeTls(state tls.ConnectionState) *Tls {
	details := &Tls{
		Version:            tls.VersionName(state.Version),
		CipherSuite:        tls.CipherSuiteName(state.CipherSuite),
		NegotiatedProtocol: state.NegotiatedProtocol,
	}

	if len(state.PeerCertificates) == 0 {
		return details
	}

	// The leaf is first; the rest of the chain says who vouched for it, which the issuer covers.
	certificate := state.PeerCertificates[0]
	if certificate == nil {
		return details
	}

	details.Subject = nameOf(certificate.Subject)
	details.Issuer = nameOf(certificate.Issuer)
	details.DnsNames = certificate.DNSNames
	details.NotBefore = certificate.NotBefore
	details.NotAfter = certificate.NotAfter

	return details
}

// nameOf renders a certificate name as its common name, falling back to the organisation for the
// certificates that carry no common name.
func nameOf(name pkix.Name) string {
	if name.CommonName != "" {
		return name.CommonName
	}

	return strings.Join(name.Organization, ", ")
}
