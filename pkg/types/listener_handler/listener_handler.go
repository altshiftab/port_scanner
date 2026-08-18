// Package listener_handler holds what a scan sends from: a reserved TCP source port and the raw
// IP sockets that carry the probes.
package listener_handler

import (
	"context"
	"errors"
	"fmt"
	"net"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftNetErrors "github.com/altshiftab/utils_go/pkg/net/errors"
	"golang.org/x/sys/unix"
)

// ListenHandler is the local end of a scan. The listen port is reserved by an open TCP listener for
// as long as the handler lives, so that no other local process can be handed the same ephemeral port
// and have its traffic mistaken for replies. Nothing is ever accepted on it: a SYN/ACK arriving for
// a listening port that has no matching connection is answered by the kernel with a RST, which is
// exactly what closes the half-open connection at the scanned host.
type ListenHandler struct {
	ListenPort        int
	TcpIpv4Connection net.PacketConn
	TcpIpv6Connection net.PacketConn

	listener net.Listener
}

// Close releases the raw sockets and the reserved port.
func (listenHandler *ListenHandler) Close() error {
	if listenHandler == nil {
		return nil
	}

	var errs []error

	if connection := listenHandler.TcpIpv4Connection; connection != nil {
		if err := connection.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tcp ipv4 connection close: %w", err))
		}
	}

	if connection := listenHandler.TcpIpv6Connection; connection != nil {
		if err := connection.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tcp ipv6 connection close: %w", err))
		}
	}

	if listener := listenHandler.listener; listener != nil {
		if err := listener.Close(); err != nil {
			errs = append(errs, fmt.Errorf("listener close: %w", err))
		}
	}

	return errors.Join(errs...)
}

// listenOnFreePort binds a TCP listener to a port chosen by the kernel and returns it together with
// the port. The listener is dual-stack when the host allows it, so the port is reserved for both
// address families.
func listenOnFreePort(ctx context.Context) (net.Listener, int, error) {
	// The wildcard address is deliberate: the port must be reserved for every local address a
	// probe may go out from.
	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(ctx, "tcp", ":0") //nolint:gosec // See above.
	if err != nil {
		return nil, 0, altshiftErrors.NewWithTrace(fmt.Errorf("net listen: %w", err))
	}

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return nil, 0, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w (net tcp addr)", altshiftErrors.ErrConversionNotOk),
			listener.Addr(),
		)
	}

	return listener, tcpAddr.Port, nil
}

// openRawSocket opens a raw IP socket for the given network ("ip4:tcp" or "ip6:tcp"), configured
// for sending only.
func openRawSocket(network string) (net.PacketConn, error) {
	connection, err := net.ListenIP(network, nil)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("net listen ip: %w", err), network)
	}

	if err := configureRawSocket(connection); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("configure raw socket: %w", err)
	}

	return connection, nil
}

// configureRawSocket tunes a raw socket for a sender that never reads. The kernel copies every
// inbound segment of the socket's protocol into its receive queue, so the receive buffer is made as
// small as the kernel allows to keep that from costing memory. SO_BROADCAST lets a probe reach a
// subnet's broadcast address without the send failing with EACCES; such probes go unanswered but a
// network given as a CIDR block contains one.
func configureRawSocket(connection *net.IPConn) error {
	rawConnection, err := connection.SyscallConn()
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("syscall conn: %w", err))
	}

	var controlErr error
	err = rawConnection.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 1); err != nil {
			controlErr = altshiftErrors.NewWithTrace(fmt.Errorf("setsockopt so rcvbuf: %w", err))
			return
		}

		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
			controlErr = altshiftErrors.NewWithTrace(fmt.Errorf("setsockopt so broadcast: %w", err))
			return
		}
	})
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("raw conn control: %w", err))
	}

	return controlErr
}

// New reserves a source port and opens the raw sockets that probes are sent from. The IPv6 socket
// is skipped when skipIpv6 is set, for hosts without IPv6. The context bounds the setup only.
func New(ctx context.Context, skipIpv6 bool) (*ListenHandler, error) {
	listener, port, err := listenOnFreePort(ctx)
	if err != nil {
		return nil, fmt.Errorf("listen on free port: %w", err)
	}

	listenHandler := &ListenHandler{ListenPort: port, listener: listener}

	listenHandler.TcpIpv4Connection, err = openRawSocket("ip4:tcp")
	if err != nil {
		_ = listenHandler.Close()
		return nil, fmt.Errorf("open raw socket (ipv4): %w", err)
	}

	if !skipIpv6 {
		listenHandler.TcpIpv6Connection, err = openRawSocket("ip6:tcp")
		if err != nil {
			_ = listenHandler.Close()
			return nil, fmt.Errorf("open raw socket (ipv6): %w", err)
		}
	}

	return listenHandler, nil
}

// Connection returns the raw socket for the destination's address family.
func (listenHandler *ListenHandler) Connection(destination net.IP) (net.PacketConn, error) {
	if listenHandler == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("listen handler"))
	}

	if destination.To4() != nil {
		if connection := listenHandler.TcpIpv4Connection; connection != nil {
			return connection, nil
		}
		return nil, altshiftErrors.NewWithTrace(nil_error.NewWithInstance("connection", "ipv4"), destination)
	}

	if destination.To16() != nil {
		if connection := listenHandler.TcpIpv6Connection; connection != nil {
			return connection, nil
		}
		return nil, altshiftErrors.NewWithTrace(nil_error.NewWithInstance("connection", "ipv6"), destination)
	}

	return nil, altshiftErrors.NewWithTrace(altshiftNetErrors.ErrUndeterminableIpVersion, destination)
}
