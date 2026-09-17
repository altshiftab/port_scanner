package banner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/altshiftab/port_scanner/pkg/banner/banner_config"
)

// testTimeout keeps the grabs in these tests short. The silent cases wait the whole of it, so it is
// the floor on how long the package's tests take.
const testTimeout = 300 * time.Millisecond

// serve runs handler against each connection a listener accepts, on a listener bound to a port the
// kernel chose. It returns the address and stops when the test does.
//
// A real listener rather than a net.Pipe: a grab sets read deadlines, writes a probe and does a TLS
// handshake, and a pipe models none of those faithfully enough to be worth trusting.
func serve(t *testing.T, handler func(net.Conn)) (string, int) {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net listen: %v", err)
	}

	var waitGroup sync.WaitGroup
	done := make(chan struct{})

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}

			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() { _ = connection.Close() }()

				if handler != nil {
					handler(connection)
				}

				// Held open until the test is finished, so that a grab reading a silent port waits
				// its timeout out rather than being handed an immediate EOF.
				<-done
			}()
		}
	}()

	t.Cleanup(func() {
		close(done)
		_ = listener.Close()
		waitGroup.Wait()
	})

	address := listener.Addr().(*net.TCPAddr)

	return address.IP.String(), address.Port
}

// speaks returns a handler that greets whoever connects, as most services do.
func speaks(greeting string) func(net.Conn) {
	return func(connection net.Conn) {
		_, _ = connection.Write([]byte(greeting))
	}
}

// silent returns a handler that says nothing, as a web server does.
func silent() func(net.Conn) {
	return func(net.Conn) {}
}

// answersHttp returns a handler that says nothing until it is asked, then answers.
func answersHttp(response string) func(net.Conn) {
	return func(connection net.Conn) {
		buffer := make([]byte, 1024)
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := connection.Read(buffer); err != nil {
			return
		}

		_, _ = connection.Write([]byte(response))
	}
}

func TestGrabAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		handler       func(net.Conn)
		port          int
		expectNil     bool
		expectService string
		expectText    string
	}{
		{
			name:          "a service that greets is read",
			handler:       speaks("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
			port:          22,
			expectService: "ssh",
			expectText:    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
		},
		{
			name:          "an smtp greeting is told from an ftp one",
			handler:       speaks("220 mail.example.com ESMTP Postfix\r\n"),
			port:          25,
			expectService: "smtp",
			expectText:    "220 mail.example.com ESMTP Postfix",
		},
		{
			name:          "a silent port is asked, and answers",
			handler:       answersHttp("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\nhello"),
			port:          80,
			expectService: "http",
			expectText:    "HTTP/1.1 200 OK Server: nginx/1.18.0 hello",
		},
		{
			name:      "a port that is open and says nothing at all yields nothing",
			handler:   silent(),
			port:      9999,
			expectNil: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			host, listenPort := serve(t, testCase.handler)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// The port the grab is told about is the logical one, which is what names the service;
			// the port it connects to is whatever the kernel handed the listener.
			connection, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(listenPort)))
			if err != nil {
				t.Fatalf("net dial: %v", err)
			}
			defer func() { _ = connection.Close() }()

			grabbed := Grab(
				ctx,
				connection,
				testCase.port,
				banner_config.WithTimeout(testTimeout),
				banner_config.WithSettleTimeout(50*time.Millisecond),
			)

			if testCase.expectNil {
				if grabbed != nil {
					t.Fatalf("Grab() = %+v, want nil", grabbed)
				}
				return
			}

			if grabbed == nil {
				t.Fatal("Grab() = nil, want a banner")
			}

			if grabbed.Service != testCase.expectService {
				t.Errorf("Service = %q, want %q", grabbed.Service, testCase.expectService)
			}

			if grabbed.Text != testCase.expectText {
				t.Errorf("Text = %q, want %q", grabbed.Text, testCase.expectText)
			}

			if len(grabbed.Raw) == 0 {
				t.Error("Raw is empty, so nothing was actually read from the wire")
			}
		})
	}
}

// TestGrabDoesNotWriteBeforeReading is the property the HTTP probe depends on being able to assume:
// a service that greets must be read, not spoken to first. A grab that wrote first would corrupt
// every protocol that expects the server to open.
func TestGrabDoesNotWriteBeforeReading(t *testing.T) {
	t.Parallel()

	received := make(chan []byte, 1)

	host, listenPort := serve(t, func(connection net.Conn) {
		_, _ = connection.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))

		buffer := make([]byte, 512)
		_ = connection.SetReadDeadline(time.Now().Add(testTimeout))
		count, err := connection.Read(buffer)
		if err != nil {
			received <- nil
			return
		}
		received <- buffer[:count]
	})

	connection, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(listenPort)))
	if err != nil {
		t.Fatalf("net dial: %v", err)
	}
	defer func() { _ = connection.Close() }()

	grabbed := Grab(context.Background(), connection, 22, banner_config.WithTimeout(testTimeout))
	if grabbed == nil || grabbed.Service != "ssh" {
		t.Fatalf("Grab() = %+v, want an ssh banner", grabbed)
	}

	select {
	case sent := <-received:
		if len(sent) > 0 {
			t.Errorf("the grab wrote %q to a service that had already greeted it", sent)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the server never finished reading")
	}
}

// TestGrabIsBounded checks the limit holds against a service that never stops talking, which is
// what a port streaming a log or a video does.
func TestGrabIsBounded(t *testing.T) {
	t.Parallel()

	const length = 512

	host, listenPort := serve(t, func(connection net.Conn) {
		chunk := []byte(strings.Repeat("A", 4096))
		for {
			if _, err := connection.Write(chunk); err != nil {
				return
			}
		}
	})

	connection, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(listenPort)))
	if err != nil {
		t.Fatalf("net dial: %v", err)
	}
	defer func() { _ = connection.Close() }()

	grabbed := Grab(
		context.Background(),
		connection,
		9999,
		banner_config.WithTimeout(testTimeout),
		banner_config.WithLength(length),
	)

	if grabbed == nil {
		t.Fatal("Grab() = nil, want a banner")
	}

	if len(grabbed.Raw) > length {
		t.Errorf("Raw is %d bytes, want at most %d", len(grabbed.Raw), length)
	}
}

// TestGrabHonoursContextCancellation keeps a cancelled scan from being held up by a silent port for
// the whole of its timeout.
func TestGrabHonoursContextCancellation(t *testing.T) {
	t.Parallel()

	host, listenPort := serve(t, silent())

	connection, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(listenPort)))
	if err != nil {
		t.Fatalf("net dial: %v", err)
	}
	defer func() { _ = connection.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	Grab(ctx, connection, 9999, banner_config.WithTimeout(30*time.Second))
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Errorf("a cancelled grab took %s, so cancellation was not honoured", elapsed)
	}
}

func TestGrabAddressDials(t *testing.T) {
	t.Parallel()

	host, listenPort := serve(t, speaks("220 ftp.example.com FTP server ready\r\n"))

	grabbed := GrabAddress(
		context.Background(),
		host,
		listenPort,
		banner_config.WithTimeout(testTimeout),
	)

	if grabbed == nil {
		t.Fatal("GrabAddress() = nil, want a banner")
	}

	if grabbed.Service != "ftp" {
		t.Errorf("Service = %q, want %q", grabbed.Service, "ftp")
	}
}

func TestGrabAddressOnNothingListening(t *testing.T) {
	t.Parallel()

	// A listener opened and closed leaves a port nothing is on, which is the case a scan meets.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net listen: %v", err)
	}
	address := listener.Addr().(*net.TCPAddr)
	_ = listener.Close()

	grabbed := GrabAddress(
		context.Background(),
		address.IP.String(),
		address.Port,
		banner_config.WithTimeout(testTimeout),
		banner_config.WithDialTimeout(testTimeout),
	)

	if grabbed != nil {
		t.Errorf("GrabAddress() = %+v, want nil where nothing is listening", grabbed)
	}
}

// TestGrabTls reads a real handshake, so that describeTls is exercised against a certificate rather
// than a struct somebody filled in.
func TestGrabTls(t *testing.T) {
	t.Parallel()

	certificate := selfSignedCertificate(t, "scanned.example.com")

	host, listenPort := serve(t, func(connection net.Conn) {
		server := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}})
		if err := server.HandshakeContext(context.Background()); err != nil {
			return
		}

		buffer := make([]byte, 1024)
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := server.Read(buffer); err != nil && !errors.Is(err, io.EOF) {
			return
		}

		_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nServer: caddy\r\n\r\n"))
	})

	connection, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(listenPort)))
	if err != nil {
		t.Fatalf("net dial: %v", err)
	}
	defer func() { _ = connection.Close() }()

	// Port 443 so the grab tries TLS first, as it would on a real one.
	grabbed := GrabTls(context.Background(), connection, 443, banner_config.WithTimeout(2*time.Second))

	if grabbed == nil {
		t.Fatal("GrabTls() = nil, want a banner")
	}

	if grabbed.Tls == nil {
		t.Fatal("Tls is nil, so the handshake was not described")
	}

	if grabbed.Tls.Subject != "scanned.example.com" {
		t.Errorf("Tls.Subject = %q, want %q", grabbed.Tls.Subject, "scanned.example.com")
	}

	if len(grabbed.Tls.DnsNames) != 1 || grabbed.Tls.DnsNames[0] != "scanned.example.com" {
		t.Errorf("Tls.DnsNames = %v, want [scanned.example.com]", grabbed.Tls.DnsNames)
	}

	if grabbed.Tls.Version == "" {
		t.Error("Tls.Version is empty")
	}

	if grabbed.Tls.NotAfter.IsZero() {
		t.Error("Tls.NotAfter is zero, so the certificate validity was not read")
	}

	// The handshake named the port and the response named the software.
	if grabbed.Service != "https" {
		t.Errorf("Service = %q, want %q", grabbed.Service, "https")
	}

	if !strings.Contains(grabbed.Text, "caddy") {
		t.Errorf("Text = %q, want it to mention the server header", grabbed.Text)
	}
}

// TestGrabAddressFindsTlsOnAnUnexpectedPort is the second-connection path: a port that says nothing
// in the clear and is not conventionally TLS still gets a handshake tried on it.
func TestGrabAddressFindsTlsOnAnUnexpectedPort(t *testing.T) {
	t.Parallel()

	certificate := selfSignedCertificate(t, "hidden.example.com")

	host, listenPort := serve(t, func(connection net.Conn) {
		server := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}})
		if err := server.HandshakeContext(context.Background()); err != nil {
			return
		}
		_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	})

	grabbed := GrabAddress(
		context.Background(),
		host,
		listenPort,
		banner_config.WithTimeout(testTimeout),
	)

	if grabbed == nil {
		t.Fatal("GrabAddress() = nil, want the TLS retry to have found something")
	}

	if grabbed.Tls == nil {
		t.Fatal("Tls is nil, so the second connection did not happen")
	}

	if grabbed.Tls.Subject != "hidden.example.com" {
		t.Errorf("Tls.Subject = %q, want %q", grabbed.Tls.Subject, "hidden.example.com")
	}
}

// TestGrabAddressWithoutTlsDoesNotRetry checks the option actually turns the second connection off.
func TestGrabAddressWithoutTlsDoesNotRetry(t *testing.T) {
	t.Parallel()

	var connectionCount int
	var mutex sync.Mutex

	host, listenPort := serve(t, func(net.Conn) {
		mutex.Lock()
		connectionCount++
		mutex.Unlock()
	})

	grabbed := GrabAddress(
		context.Background(),
		host,
		listenPort,
		banner_config.WithTimeout(testTimeout),
		banner_config.WithTls(false),
	)

	if grabbed != nil {
		t.Errorf("GrabAddress() = %+v, want nil", grabbed)
	}

	mutex.Lock()
	defer mutex.Unlock()

	if connectionCount != 1 {
		t.Errorf("the silent port was connected to %d times, want 1 with TLS off", connectionCount)
	}
}

func TestGrabRejectsNilConnection(t *testing.T) {
	t.Parallel()

	if grabbed := Grab(context.Background(), nil, 22); grabbed != nil {
		t.Errorf("Grab(nil) = %+v, want nil", grabbed)
	}

	if grabbed := GrabTls(context.Background(), nil, 443); grabbed != nil {
		t.Errorf("GrabTls(nil) = %+v, want nil", grabbed)
	}

	if grabbed := GrabAddress(context.Background(), "", 443); grabbed != nil {
		t.Errorf("GrabAddress(\"\") = %+v, want nil", grabbed)
	}
}

// selfSignedCertificate mints a certificate for the TLS tests, so that they need nothing on disk.
func selfSignedCertificate(t *testing.T, name string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509 create certificate: %v", err)
	}

	parsed, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatalf("x509 parse certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{encoded},
		PrivateKey:  key,
		Leaf:        parsed,
	}
}
