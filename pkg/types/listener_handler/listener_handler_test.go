package listener_handler

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftNetErrors "github.com/altshiftab/utils_go/pkg/net/errors"
)

// fakePacketConn is a net.PacketConn that records whether it was closed.
type fakePacketConn struct {
	closed   bool
	closeErr error
}

func (conn *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (conn *fakePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}
func (conn *fakePacketConn) Close() error {
	conn.closed = true
	return conn.closeErr
}
func (conn *fakePacketConn) LocalAddr() net.Addr              { return nil }
func (conn *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (conn *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (conn *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

var errCloseFailed = errors.New("close failed")

func TestConnection(t *testing.T) {
	t.Parallel()

	ipv4Conn := &fakePacketConn{}
	ipv6Conn := &fakePacketConn{}

	testCases := []struct {
		name          string
		listenHandler *ListenHandler
		destination   net.IP
		want          net.PacketConn
		wantNilError  bool
		wantErr       error
	}{
		{
			name:          "ipv4",
			listenHandler: &ListenHandler{TcpIpv4Connection: ipv4Conn, TcpIpv6Connection: ipv6Conn},
			destination:   net.ParseIP("192.0.2.1"),
			want:          ipv4Conn,
		},
		{
			name:          "ipv4 in four-byte form",
			listenHandler: &ListenHandler{TcpIpv4Connection: ipv4Conn, TcpIpv6Connection: ipv6Conn},
			destination:   net.ParseIP("192.0.2.1").To4(),
			want:          ipv4Conn,
		},
		{
			name:          "ipv6",
			listenHandler: &ListenHandler{TcpIpv4Connection: ipv4Conn, TcpIpv6Connection: ipv6Conn},
			destination:   net.ParseIP("2001:db8::1"),
			want:          ipv6Conn,
		},
		{
			name:          "ipv6 without an ipv6 socket",
			listenHandler: &ListenHandler{TcpIpv4Connection: ipv4Conn},
			destination:   net.ParseIP("2001:db8::1"),
			wantNilError:  true,
		},
		{
			name:          "ipv4 without an ipv4 socket",
			listenHandler: &ListenHandler{TcpIpv6Connection: ipv6Conn},
			destination:   net.ParseIP("192.0.2.1"),
			wantNilError:  true,
		},
		{
			name:          "nil handler",
			listenHandler: nil,
			destination:   net.ParseIP("192.0.2.1"),
			wantNilError:  true,
		},
		{
			name:          "not an ip",
			listenHandler: &ListenHandler{TcpIpv4Connection: ipv4Conn, TcpIpv6Connection: ipv6Conn},
			destination:   net.IP{1, 2, 3},
			wantErr:       altshiftNetErrors.ErrUndeterminableIpVersion,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := testCase.listenHandler.Connection(testCase.destination)
			if testCase.wantNilError {
				if _, ok := errors.AsType[*nil_error.Error](err); !ok {
					t.Fatalf("Connection() error = %v, want a nil error", err)
				}
				return
			}
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("Connection() error = %v, want %v", err, testCase.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Connection() error = %v", err)
			}
			if got != testCase.want {
				t.Fatalf("Connection() = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestClose(t *testing.T) {
	t.Parallel()

	closeErr := errCloseFailed

	testCases := []struct {
		name          string
		listenHandler *ListenHandler
		wantErr       error
	}{
		{name: "nil handler", listenHandler: nil},
		{name: "empty handler", listenHandler: &ListenHandler{}},
		{
			name: "both sockets",
			listenHandler: &ListenHandler{
				TcpIpv4Connection: &fakePacketConn{},
				TcpIpv6Connection: &fakePacketConn{},
			},
		},
		{
			name: "one socket fails",
			listenHandler: &ListenHandler{
				TcpIpv4Connection: &fakePacketConn{closeErr: closeErr},
				TcpIpv6Connection: &fakePacketConn{},
			},
			wantErr: closeErr,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := testCase.listenHandler.Close()
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("Close() error = %v, want %v", err, testCase.wantErr)
			}

			if testCase.listenHandler == nil {
				return
			}

			// Every socket is closed even when one of them fails.
			for _, connection := range []net.PacketConn{
				testCase.listenHandler.TcpIpv4Connection,
				testCase.listenHandler.TcpIpv6Connection,
			} {
				if fake, ok := connection.(*fakePacketConn); ok && !fake.closed {
					t.Errorf("a socket was not closed")
				}
			}
		})
	}
}

func TestListenOnFreePort(t *testing.T) {
	t.Parallel()

	listener, port, err := listenOnFreePort(t.Context())
	if err != nil {
		t.Fatalf("listenOnFreePort() error = %v", err)
	}
	defer func() { _ = listener.Close() }()

	if port < 1 || port > 65535 {
		t.Fatalf("port = %d, want a port number", port)
	}

	// The port is reserved: nothing else can listen on it while the listener is open.
	listenConfig := net.ListenConfig{}
	if other, err := listenConfig.Listen(t.Context(), "tcp", listener.Addr().String()); err == nil {
		_ = other.Close()
		t.Fatalf("the reserved port could be listened on again")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		skipIpv6 bool
	}{
		{name: "ipv4 only", skipIpv6: true},
		{name: "ipv4 and ipv6", skipIpv6: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			listenHandler, err := New(t.Context(), testCase.skipIpv6)
			if err != nil {
				if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
					t.Skip("raw sockets need CAP_NET_RAW; run with it to exercise New")
				}
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				if err := listenHandler.Close(); err != nil {
					t.Errorf("Close() error = %v", err)
				}
			}()

			if listenHandler.ListenPort == 0 {
				t.Errorf("ListenPort = 0")
			}
			if listenHandler.TcpIpv4Connection == nil {
				t.Errorf("TcpIpv4Connection = nil")
			}
			if (listenHandler.TcpIpv6Connection == nil) != testCase.skipIpv6 {
				t.Errorf("TcpIpv6Connection = %v, skipIpv6 = %v", listenHandler.TcpIpv6Connection, testCase.skipIpv6)
			}
		})
	}
}
