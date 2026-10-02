package port_scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"sync/atomic"
	"syscall"

	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
)

const (
	// captureLength is how much of each captured packet is kept. A reply is a bare TCP header, but
	// the full packet is cheap and keeps the decoder from ever seeing a truncated one.
	captureLength = 65536
)

// CaptureHandle is a packet socket bound to one interface, delivering the packets its filter
// accepts.
//
// The socket is AF_PACKET of type SOCK_DGRAM: the kernel strips each frame's link-layer header and
// hands over the packet from its IP header on, whatever the interface's framing. Ethernet, a VLAN,
// loopback and a tunnel that has no link-layer header at all (WireGuard, ipip) therefore look
// alike to the filter and the decoder, which neither has to know what the interface is.
type CaptureHandle struct {
	file    *os.File
	rawConn syscall.RawConn
	buffer  []byte
	closed  atomic.Bool
}

// Close closes the handle, waking any reader blocked on it.
func (handle *CaptureHandle) Close() error {
	handle.closed.Store(true)

	if err := handle.file.Close(); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("file close: %w", err))
	}

	return nil
}

// Closed reports whether the handle has been closed.
//
// A reader needs this to tell the scan ending from the capture failing: the
// read error raised by a closed socket arrives with its cause formatted away,
// so it cannot be recognised by inspecting the error itself.
func (handle *CaptureHandle) Closed() bool {
	return handle.closed.Load()
}

// ReadPacketData blocks until the filter accepts an inbound IPv4 or IPv6 packet and returns a copy
// of it, starting at its IP header. Packets the host itself sends are passed over: a reply always
// arrives, and on loopback, where every packet is seen leaving as well as arriving, this keeps each
// from being read twice.
//
// It is safe for concurrent use, though concurrent readers split the packets between them.
func (handle *CaptureHandle) ReadPacketData() ([]byte, error) {
	for {
		var data []byte
		var from unix.Sockaddr
		var recvErr error

		// The buffer is shared, so the packet is copied out of it while the read lock that the
		// callback runs under still keeps any other reader from filling it.
		err := handle.rawConn.Read(func(fd uintptr) bool {
			var length int
			length, from, recvErr = unix.Recvfrom(int(fd), handle.buffer, 0)
			if recvErr == nil {
				data = slices.Clone(handle.buffer[:length])
			}
			return !errors.Is(recvErr, unix.EAGAIN)
		})
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("raw conn read: %w", err))
		}
		if errors.Is(recvErr, unix.EINTR) {
			continue
		}
		if recvErr != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("recvfrom: %w", recvErr))
		}

		linkLayerAddress, ok := from.(*unix.SockaddrLinklayer)
		if !ok || linkLayerAddress.Pkttype == unix.PACKET_OUTGOING {
			continue
		}

		switch linkLayerAddress.Protocol {
		case htons(unix.ETH_P_IP), htons(unix.ETH_P_IPV6):
			return data, nil
		}
	}
}

// htons converts a value to network byte order, as socket addresses carry protocol numbers.
func htons(value uint16) uint16 {
	var networkOrder [2]byte
	binary.BigEndian.PutUint16(networkOrder[:], value)

	return binary.NativeEndian.Uint16(networkOrder[:])
}

// OpenCaptureHandle opens a capture handle on the named interface, filtered to
// what the given program accepts.
//
// The handle is an AF_PACKET socket opened directly rather than through
// libpcap, which is what keeps this package free of cgo. Packets are delivered
// as they arrive - there is no buffering delay to configure, as there was with
// libpcap's immediate mode.
//
// The socket is opened listening to no protocol, given its filter, and only then bound to the
// interface and to every protocol, so no packet reaches it unfiltered.
func OpenCaptureHandle(interfaceName string, filter []bpf.RawInstruction) (*CaptureHandle, error) {
	if interfaceName == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("interface name"))
	}

	if len(filter) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("filter"))
	}

	networkInterface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("net interface by name: %w", err),
			interfaceName,
		)
	}
	if networkInterface == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("network interface"), interfaceName)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("socket: %w", err), interfaceName)
	}

	socketFilter := make([]unix.SockFilter, len(filter))
	for i, instruction := range filter {
		socketFilter[i] = unix.SockFilter{
			Code: instruction.Op,
			Jt:   instruction.Jt,
			Jf:   instruction.Jf,
			K:    instruction.K,
		}
	}
	program := &unix.SockFprog{Len: uint16(len(socketFilter)), Filter: &socketFilter[0]} //nolint:gosec // A classic BPF program is far shorter.
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, program); err != nil {
		_ = unix.Close(fd)
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("setsockopt so attach filter: %w", err), interfaceName)
	}

	address := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: networkInterface.Index}
	if err := unix.Bind(fd, address); err != nil {
		_ = unix.Close(fd)
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("bind: %w", err), interfaceName)
	}

	// The descriptor is non-blocking, so the file registers it with the runtime poller: a read
	// parks the goroutine rather than a thread, and closing the file wakes it.
	file := os.NewFile(uintptr(fd), "packet:"+interfaceName)
	if file == nil {
		_ = unix.Close(fd)
		return nil, altshiftErrors.NewWithTrace(nil_error.New("file"), interfaceName)
	}

	rawConn, err := file.SyscallConn()
	if err != nil {
		_ = file.Close()
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("file syscall conn: %w", err), interfaceName)
	}

	return &CaptureHandle{file: file, rawConn: rawConn, buffer: make([]byte, captureLength)}, nil
}

// OpenCaptureHandles opens a capture handle for replies to listenPort on every interface that is up,
// or on the named ones only when interfaceNames is not empty. A reply comes back on whichever
// interface the route to its sender uses, and with more than one interface up that need not be the
// same one for every target, so all of them are captured on. An interface that cannot be opened is
// logged and skipped, and it is an error only if none could be; an interface that was named must
// open, and is an error otherwise.
func OpenCaptureHandles(
	ctx context.Context,
	listenPort int,
	interfaceNames []string,
) ([]*CaptureHandle, error) {
	if listenPort < 1 || listenPort > maxPort {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w: %d", altshiftErrors.ErrValidationError, portScannerErrors.ErrInvalidPort, listenPort),
			listenPort,
		)
	}

	networkInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("net interfaces: %w", err))
	}

	upInterfaceNames := make([]string, 0, len(networkInterfaces))
	for _, networkInterface := range networkInterfaces {
		if networkInterface.Flags&net.FlagUp != 0 {
			upInterfaceNames = append(upInterfaceNames, networkInterface.Name)
		}
	}

	if len(interfaceNames) != 0 {
		for _, interfaceName := range interfaceNames {
			if !slices.Contains(upInterfaceNames, interfaceName) {
				return nil, altshiftErrors.NewWithTrace(
					fmt.Errorf(
						"%w: %w: %s",
						altshiftErrors.ErrValidationError, portScannerErrors.ErrInterfaceNotUp, interfaceName,
					),
					interfaceName,
				)
			}
		}
		upInterfaceNames = interfaceNames
	}

	filter, err := ReplyFilter(listenPort)
	if err != nil {
		return nil, fmt.Errorf("reply filter: %w", err)
	}

	var handles []*CaptureHandle
	var openErrors []error

	for _, interfaceName := range upInterfaceNames {
		handle, err := OpenCaptureHandle(interfaceName, filter)
		if err != nil {
			wrappedErr := altshiftErrors.New(fmt.Errorf("open capture handle: %w", err), interfaceName)
			if len(interfaceNames) != 0 {
				CloseCaptureHandles(handles)
				return nil, wrappedErr
			}

			openErrors = append(openErrors, wrappedErr)
			slog.WarnContext(
				altshiftContext.WithError(ctx, wrappedErr),
				"A capture handle could not be opened on an interface. Skipping the interface.",
			)
			continue
		}

		handles = append(handles, handle)
	}

	if len(handles) == 0 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", portScannerErrors.ErrNoCaptureHandles, errors.Join(openErrors...)),
			interfaceNames,
		)
	}

	return handles, nil
}

// CloseCaptureHandles closes every handle. A reader blocked on a handle is woken by
// the close and returns an error, which is how it learns the scan is over - an
// AF_PACKET read has no timeout of its own to return on.
//
// It is therefore what frees a reader still parked when Scan returned, and should be called as soon
// as the scan is done with the handles.
func CloseCaptureHandles(handles []*CaptureHandle) {
	for _, handle := range handles {
		if handle != nil {
			_ = handle.Close()
		}
	}
}
