package port_scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"time"

	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/gopacket/gopacket/pcap"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
)

const (
	// snapLength is how much of each captured packet is kept. A reply is a bare TCP header, but the
	// full frame is cheap and keeps the decoder from ever seeing a truncated one.
	snapLength = 65536
	// readTimeout bounds how long a read on a capture handle blocks when no packet arrives. It is
	// how quickly a reader notices that the scan is over; packets themselves are delivered at once,
	// since the handles are in immediate mode.
	readTimeout = 200 * time.Millisecond
)

// ReplyFilter returns the BPF filter that keeps only what could be a reply to a probe sent from
// listenPort: TCP segments addressed to that port.
func ReplyFilter(listenPort int) string {
	return fmt.Sprintf("tcp and dst port %d", listenPort)
}

// OpenPcapHandle opens a capture handle on the named interface with the given BPF filter, in
// immediate mode so that replies are delivered as they arrive.
func OpenPcapHandle(interfaceName string, bpfFilter string) (*pcap.Handle, error) {
	if interfaceName == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("interface name"))
	}

	if bpfFilter == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("bpf filter"))
	}

	inactiveHandle, err := pcap.NewInactiveHandle(interfaceName)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("pcap new inactive handle: %w", err), interfaceName)
	}
	defer inactiveHandle.CleanUp()

	if err := inactiveHandle.SetSnapLen(snapLength); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("inactive handle set snap len: %w", err), snapLength)
	}

	if err := inactiveHandle.SetTimeout(readTimeout); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("inactive handle set timeout: %w", err), readTimeout)
	}

	if err := inactiveHandle.SetImmediateMode(true); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("inactive handle set immediate mode: %w", err))
	}

	handle, err := inactiveHandle.Activate()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("inactive handle activate: %w", err), interfaceName)
	}
	if handle == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("handle"), interfaceName)
	}

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("handle set bpf filter: %w", err), bpfFilter)
	}

	return handle, nil
}

// OpenPcapHandles opens a capture handle for replies to listenPort on every interface that is up,
// or on the named ones only when interfaceNames is not empty. A reply comes back on whichever
// interface the route to its sender uses, and with more than one interface up that need not be the
// same one for every target, so all of them are captured on. An interface that cannot be opened is
// logged and skipped, and it is an error only if none could be; an interface that was named must
// open, and is an error otherwise.
func OpenPcapHandles(ctx context.Context, listenPort int, interfaceNames []string) ([]*pcap.Handle, error) {
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

	bpfFilter := ReplyFilter(listenPort)

	var handles []*pcap.Handle
	var openErrors []error

	for _, interfaceName := range upInterfaceNames {
		handle, err := OpenPcapHandle(interfaceName, bpfFilter)
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

// ClosePcapHandles closes every handle. A reader blocked on a handle returns from its read within
// the read timeout and then sees the handle closed; Close waits for that read to finish.
func ClosePcapHandles(handles []*pcap.Handle) {
	for _, handle := range handles {
		if handle != nil {
			handle.Close()
		}
	}
}
