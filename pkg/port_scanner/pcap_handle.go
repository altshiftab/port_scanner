package port_scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync/atomic"

	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/net/bpf"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
)

const (
	// snapLength is how much of each captured packet is kept. A reply is a bare TCP header, but the
	// full frame is cheap and keeps the decoder from ever seeing a truncated one.
	snapLength = 65536
)

// CaptureHandle is a capture handle together with the link type of the frames
// it delivers.
//
// AF_PACKET hands over each frame with the interface's own link-layer header,
// but pcapgo does not report which kind that is - libpcap did, through
// LinkType. It is therefore derived from the interface itself.
type CaptureHandle struct {
	*pcapgo.EthernetHandle

	linkType layers.LinkType
	closed   atomic.Bool
}

// Close closes the handle, waking any reader blocked on it.
func (handle *CaptureHandle) Close() error {
	handle.closed.Store(true)

	if err := handle.EthernetHandle.Close(); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("ethernet handle close: %w", err))
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

// LinkType reports the link type of the frames this handle delivers.
func (handle *CaptureHandle) LinkType() layers.LinkType {
	return handle.linkType
}

// interfaceLinkType reports how frames captured on the interface are framed.
//
// An interface with a six-byte hardware address is Ethernet. Loopback is too:
// Linux gives loopback frames a placeholder Ethernet header even though the
// interface has no address. What is left - a tunnel, most often - carries bare
// IP packets.
func interfaceLinkType(networkInterface *net.Interface) layers.LinkType {
	if networkInterface == nil {
		return layers.LinkTypeEthernet
	}

	if networkInterface.Flags&net.FlagLoopback != 0 {
		return layers.LinkTypeEthernet
	}

	if len(networkInterface.HardwareAddr) == 6 {
		return layers.LinkTypeEthernet
	}

	return linkTypeDltRaw
}

// OpenPcapHandle opens a capture handle on the named interface, filtered to
// what the given program accepts.
//
// The handle is an AF_PACKET socket opened directly rather than through
// libpcap, which is what keeps this package free of cgo. Packets are delivered
// as they arrive - there is no buffering delay to configure, as there was with
// libpcap's immediate mode.
func OpenPcapHandle(interfaceName string, filter []bpf.RawInstruction) (*CaptureHandle, error) {
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

	handle, err := pcapgo.NewEthernetHandle(interfaceName)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("pcapgo new ethernet handle: %w", err),
			interfaceName,
		)
	}
	if handle == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("handle"), interfaceName)
	}

	if err := handle.SetCaptureLength(snapLength); err != nil {
		_ = handle.Close()
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("handle set capture length: %w", err),
			snapLength,
		)
	}

	// The filter is applied after the socket is open, so a frame that arrives in
	// between is accepted. That is harmless here: the scanner matches replies
	// against the probes it sent, and an unexpected frame matches none of them.
	if err := handle.SetBPF(filter); err != nil {
		_ = handle.Close()
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("handle set bpf: %w", err))
	}

	return &CaptureHandle{EthernetHandle: handle, linkType: interfaceLinkType(networkInterface)}, nil
}

// OpenPcapHandles opens a capture handle for replies to listenPort on every interface that is up,
// or on the named ones only when interfaceNames is not empty. A reply comes back on whichever
// interface the route to its sender uses, and with more than one interface up that need not be the
// same one for every target, so all of them are captured on. An interface that cannot be opened is
// logged and skipped, and it is an error only if none could be; an interface that was named must
// open, and is an error otherwise.
func OpenPcapHandles(
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
		handle, err := OpenPcapHandle(interfaceName, filter)
		if err != nil {
			wrappedErr := altshiftErrors.New(fmt.Errorf("open pcap handle: %w", err), interfaceName)
			if len(interfaceNames) != 0 {
				ClosePcapHandles(handles)
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

// ClosePcapHandles closes every handle. A reader blocked on a handle is woken by
// the close and returns an error, which is how it learns the scan is over - an
// AF_PACKET read has no timeout of its own to return on.
//
// It is therefore what frees a reader still parked when Scan returned, and should be called as soon
// as the scan is done with the handles.
func ClosePcapHandles(handles []*CaptureHandle) {
	for _, handle := range handles {
		if handle != nil {
			_ = handle.Close()
		}
	}
}
