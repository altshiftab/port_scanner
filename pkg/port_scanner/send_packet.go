package port_scanner

import (
	"fmt"
	"net"
	"net/netip"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/net/packet"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
)

const (
	// probeWindow is the receive window advertised by a probe. The value is arbitrary; a real
	// window is never needed since the connection is reset as soon as the reply arrives.
	probeWindow = 1024
	// probeMss is the maximum segment size option a probe carries, so that it looks like an
	// ordinary connection attempt.
	probeMss = 1460
	// tcpOptionKindMss and tcpOptionLengthMss make up the MSS option's kind and length bytes.
	tcpOptionKindMss   = 2
	tcpOptionLengthMss = 4
)

// NewProbe returns a SYN probe from sourcePort to destinationPort with the given sequence number.
func NewProbe(sourcePort int, destinationPort int, sequenceNumber uint32) (*packet.Tcp, error) {
	for _, port := range []int{sourcePort, destinationPort} {
		if port < 1 || port > maxPort {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: %w: %d", altshiftErrors.ErrValidationError, portScannerErrors.ErrInvalidPort, port),
				port,
			)
		}
	}

	return &packet.Tcp{
		SourcePort:      uint16(sourcePort),      //nolint:gosec // Range checked above.
		DestinationPort: uint16(destinationPort), //nolint:gosec // Range checked above.
		Sequence:        sequenceNumber,
		Flags:           packet.TcpFlagSyn,
		Window:          probeWindow,
		Options:         []byte{tcpOptionKindMss, tcpOptionLengthMss, probeMss >> 8, probeMss & 0xff},
	}, nil
}

// probeAddress converts an address to the form a probe's checksum is computed over: an IPv4
// address as IPv4, however net stored it.
func probeAddress(ip net.IP) (netip.Addr, error) {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, altshiftErrors.NewWithTrace(portScannerErrors.ErrUnsupportedNetworkLayer, ip)
	}

	return address.Unmap(), nil
}

// SendTcpPacket encodes the segment, with its checksum computed over the pseudo-header of source
// and destination, into buffer and writes it to destination through connection, a raw socket of
// the matching family; the kernel builds the IP header. Source must be the address the kernel will
// send from, or the checksum will not hold. The buffer is returned for the next call to reuse.
func SendTcpPacket(
	tcp *packet.Tcp,
	source netip.Addr,
	destination netip.Addr,
	connection net.PacketConn,
	buffer []byte,
) ([]byte, error) {
	if tcp == nil {
		return buffer, altshiftErrors.NewWithTrace(nil_error.New("tcp"))
	}

	if connection == nil {
		return buffer, altshiftErrors.NewWithTrace(nil_error.New("connection"))
	}

	buffer, err := packet.AppendTcp(buffer[:0], tcp, source, destination)
	if err != nil {
		return buffer, altshiftErrors.NewWithTrace(fmt.Errorf("append tcp: %w", err), source, destination)
	}

	destinationIp := net.IP(destination.AsSlice())
	if _, err := connection.WriteTo(buffer, &net.IPAddr{IP: destinationIp}); err != nil {
		return buffer, altshiftErrors.NewWithTrace(fmt.Errorf("packet conn write to: %w", err), destinationIp)
	}

	return buffer, nil
}
