package port_scanner

import (
	"fmt"
	"net"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
)

const (
	// probeWindow is the receive window advertised by a probe. The value is arbitrary; a real
	// window is never needed since the connection is reset as soon as the reply arrives.
	probeWindow = 1024
	// probeMss is the maximum segment size option a probe carries, so that it looks like an
	// ordinary connection attempt.
	probeMss = 1460
	// probeTtl is the TTL / hop limit written into the network layer of a probe. That layer is not
	// what goes on the wire — the kernel builds the real IP header, with its own TTL — it only
	// supplies the checksum pseudo-header, in which the TTL plays no part; the value is nominal.
	probeTtl = 255
)

var serializeOptions = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

// NewProbeTcpLayer returns the TCP layer of a SYN probe from sourcePort to destinationPort with
// the given sequence number.
func NewProbeTcpLayer(sourcePort int, destinationPort int, sequenceNumber uint32) (*layers.TCP, error) {
	for _, port := range []int{sourcePort, destinationPort} {
		if port < 1 || port > maxPort {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: %w: %d", altshiftErrors.ErrValidationError, portScannerErrors.ErrInvalidPort, port),
				port,
			)
		}
	}

	return &layers.TCP{
		SrcPort: layers.TCPPort(sourcePort),      //nolint:gosec // Range checked above.
		DstPort: layers.TCPPort(destinationPort), //nolint:gosec // Range checked above.
		Seq:     sequenceNumber,
		Window:  probeWindow,
		SYN:     true,
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{probeMss >> 8, probeMss & 0xff},
			},
		},
	}, nil
}

// NewProbeNetworkLayer returns the network layer of a probe from sourceIp to destinationIp. The
// layer is not sent: the raw sockets have the kernel build the IP header. It supplies the checksum
// pseudo-header, which is why its source address must be the one the kernel will use.
func NewProbeNetworkLayer(sourceIp net.IP, destinationIp net.IP) (gopacket.NetworkLayer, error) {
	if len(sourceIp) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("source ip"))
	}

	if len(destinationIp) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("destination ip"))
	}

	if destinationIp.To4() != nil {
		return &layers.IPv4{
			Version:  4,
			TTL:      probeTtl,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    sourceIp,
			DstIP:    destinationIp,
		}, nil
	}

	if destinationIp.To16() != nil {
		return &layers.IPv6{
			Version:    6,
			HopLimit:   probeTtl,
			NextHeader: layers.IPProtocolTCP,
			SrcIP:      sourceIp,
			DstIP:      destinationIp,
		}, nil
	}

	return nil, altshiftErrors.NewWithTrace(portScannerErrors.ErrUnsupportedNetworkLayer, destinationIp)
}

// SendTcpPacket serializes the TCP layer, with its checksum computed over networkLayer, and writes
// it to the network layer's destination through connection, a raw socket of the matching family.
func SendTcpPacket(
	tcpLayer *layers.TCP,
	networkLayer gopacket.NetworkLayer,
	connection net.PacketConn,
	buffer gopacket.SerializeBuffer,
) error {
	if tcpLayer == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("tcp layer"))
	}

	if networkLayer == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("network layer"))
	}

	if connection == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("connection"))
	}

	if buffer == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("buffer"))
	}

	var destinationIp net.IP
	switch typedNetworkLayer := networkLayer.(type) {
	case *layers.IPv4:
		destinationIp = typedNetworkLayer.DstIP
	case *layers.IPv6:
		destinationIp = typedNetworkLayer.DstIP
	default:
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %T", portScannerErrors.ErrUnsupportedNetworkLayer, networkLayer),
		)
	}

	if len(destinationIp) == 0 {
		return altshiftErrors.NewWithTrace(empty_error.New("destination ip"))
	}

	if err := tcpLayer.SetNetworkLayerForChecksum(networkLayer); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("tcp layer set network layer for checksum: %w", err))
	}

	if err := buffer.Clear(); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("serialize buffer clear: %w", err))
	}

	if err := gopacket.SerializeLayers(buffer, serializeOptions, tcpLayer); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("gopacket serialize layers: %w", err))
	}

	if _, err := connection.WriteTo(buffer.Bytes(), &net.IPAddr{IP: destinationIp}); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("packet conn write to: %w", err), destinationIp)
	}

	return nil
}
