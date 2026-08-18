package port_scanner

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// packetSpec describes a packet to build for a test.
type packetSpec struct {
	linkType layers.LinkType
	vlan     bool
	// ipv6DestinationOptions inserts a Destination Options extension header between the IPv6
	// header and the transport header.
	ipv6DestinationOptions bool
	sourceIp               string
	destinationIp          string
	sourcePort             uint16
	destPort               uint16
	seq                    uint32
	ack                    uint32
	syn                    bool
	ackFlag                bool
	rst                    bool
	udp                    bool
	payload                []byte
}

// buildPacket serializes the described packet with the framing its link type calls for.
func buildPacket(t *testing.T, spec *packetSpec) []byte {
	t.Helper()

	sourceIp := net.ParseIP(spec.sourceIp)
	destinationIp := net.ParseIP(spec.destinationIp)
	if sourceIp == nil || destinationIp == nil {
		t.Fatalf("bad addresses %q, %q", spec.sourceIp, spec.destinationIp)
	}

	var stack []gopacket.SerializableLayer
	var networkLayer gopacket.NetworkLayer
	var etherType layers.EthernetType
	var ipProtocol layers.IPProtocol

	if spec.udp {
		ipProtocol = layers.IPProtocolUDP
	} else {
		ipProtocol = layers.IPProtocolTCP
	}

	var extensionLayers []gopacket.SerializableLayer
	if sourceIp.To4() != nil {
		etherType = layers.EthernetTypeIPv4
		networkLayer = &layers.IPv4{
			Version: 4, TTL: 64, Protocol: ipProtocol, SrcIP: sourceIp.To4(), DstIP: destinationIp.To4(),
		}
	} else {
		etherType = layers.EthernetTypeIPv6
		nextHeader := ipProtocol
		if spec.ipv6DestinationOptions {
			nextHeader = layers.IPProtocolIPv6Destination
			// A PadN option of four bytes brings the header to the eight-byte multiple it must be.
			destinationOptions := &layers.IPv6Destination{
				Options: []*layers.IPv6DestinationOption{{OptionType: 1, OptionLength: 4, OptionData: make([]byte, 4)}},
			}
			destinationOptions.NextHeader = ipProtocol
			extensionLayers = append(extensionLayers, destinationOptions)
		}
		networkLayer = &layers.IPv6{
			Version: 6, HopLimit: 64, NextHeader: nextHeader, SrcIP: sourceIp, DstIP: destinationIp,
		}
	}

	switch spec.linkType {
	case layers.LinkTypeEthernet:
		if spec.vlan {
			stack = append(stack,
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{2, 0, 0, 0, 0, 1},
					DstMAC:       net.HardwareAddr{2, 0, 0, 0, 0, 2},
					EthernetType: layers.EthernetTypeDot1Q,
				},
				&layers.Dot1Q{VLANIdentifier: 7, Type: etherType},
			)
		} else {
			stack = append(stack, &layers.Ethernet{
				SrcMAC:       net.HardwareAddr{2, 0, 0, 0, 0, 1},
				DstMAC:       net.HardwareAddr{2, 0, 0, 0, 0, 2},
				EthernetType: etherType,
			})
		}
	case layers.LinkTypeLinuxSLL, layers.LinkTypeLinuxSLL2:
		// gopacket decodes but does not serialize Linux cooked capture; its header is prepended
		// by hand below.
	default:
		// Bare IP: no link-layer framing.
	}

	serializable, ok := networkLayer.(gopacket.SerializableLayer)
	if !ok {
		t.Fatalf("network layer is not serializable")
	}
	stack = append(stack, serializable)
	stack = append(stack, extensionLayers...)

	if spec.udp {
		udp := &layers.UDP{SrcPort: layers.UDPPort(spec.sourcePort), DstPort: layers.UDPPort(spec.destPort)}
		if err := udp.SetNetworkLayerForChecksum(networkLayer); err != nil {
			t.Fatalf("SetNetworkLayerForChecksum() error = %v", err)
		}
		stack = append(stack, udp)
	} else {
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(spec.sourcePort),
			DstPort: layers.TCPPort(spec.destPort),
			Seq:     spec.seq,
			Ack:     spec.ack,
			SYN:     spec.syn,
			ACK:     spec.ackFlag,
			RST:     spec.rst,
			Window:  65535,
		}
		if err := tcp.SetNetworkLayerForChecksum(networkLayer); err != nil {
			t.Fatalf("SetNetworkLayerForChecksum() error = %v", err)
		}
		stack = append(stack, tcp)
	}

	if len(spec.payload) != 0 {
		stack = append(stack, gopacket.Payload(spec.payload))
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, stack...); err != nil {
		t.Fatalf("SerializeLayers() error = %v", err)
	}

	switch spec.linkType {
	case layers.LinkTypeLinuxSLL:
		// Packet type (2), ARPHRD type (2), address length (2), address (8), protocol (2).
		header := []byte{
			0x00, 0x00, // packet type: to us
			0x00, 0x01, // ARPHRD_ETHER
			0x00, 0x06, // address length
			0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // address, padded
		}
		header = binary.BigEndian.AppendUint16(header, uint16(etherType)) // protocol

		return append(header, buffer.Bytes()...)
	case layers.LinkTypeLinuxSLL2:
		// Protocol (2), reserved (2), interface index (4), ARPHRD type (2), packet type (1),
		// address length (1), address (8).
		header := binary.BigEndian.AppendUint16(nil, uint16(etherType))
		header = append(header,
			0x00, 0x00, // reserved
			0x00, 0x00, 0x00, 0x02, // interface index
			0x00, 0x01, // ARPHRD_ETHER
			0x00,                                           // packet type: to us
			0x06,                                           // address length
			0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // address, padded
		)

		return append(header, buffer.Bytes()...)
	default:
		return buffer.Bytes()
	}
}

// fakePacketSource hands out queued packets and behaves like an idle capture handle otherwise:
// reads time out until it is closed, after which they report EOF.
type fakePacketSource struct {
	linkType layers.LinkType
	packets  chan []byte
	done     chan struct{}
	once     sync.Once
}

func newFakePacketSource(linkType layers.LinkType) *fakePacketSource {
	return &fakePacketSource{
		linkType: linkType,
		packets:  make(chan []byte, 1024),
		done:     make(chan struct{}),
	}
}

func (source *fakePacketSource) LinkType() layers.LinkType {
	return source.linkType
}

func (source *fakePacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	select {
	case <-source.done:
		return nil, gopacket.CaptureInfo{}, io.EOF
	case data := <-source.packets:
		return data, gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}, nil
	case <-time.After(5 * time.Millisecond):
		return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
	}
}

func (source *fakePacketSource) inject(data []byte) {
	source.packets <- data
}

func (source *fakePacketSource) close() {
	source.once.Do(func() { close(source.done) })
}

var errNotAnIpAddress = errors.New("address is not an ip address")

// sentProbe is a probe as a fakePacketConn saw it: the segment decoded, and where it went.
type sentProbe struct {
	destination net.IP
	tcp         layers.TCP
}

// fakePacketConn stands in for a raw socket. It decodes each written segment and hands it to
// onSend, which a test uses to answer it.
type fakePacketConn struct {
	onSend   func(probe *sentProbe)
	writeErr error

	mu    sync.Mutex
	sent  []*sentProbe
	count int
}

func (conn *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }

func (conn *fakePacketConn) WriteTo(data []byte, address net.Addr) (int, error) {
	conn.mu.Lock()
	conn.count++
	conn.mu.Unlock()

	if conn.writeErr != nil {
		return 0, conn.writeErr
	}

	ipAddr, ok := address.(*net.IPAddr)
	if !ok {
		return 0, errNotAnIpAddress
	}

	var tcp layers.TCP
	if err := tcp.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return 0, err
	}

	probe := &sentProbe{destination: ipAddr.IP, tcp: tcp}

	conn.mu.Lock()
	conn.sent = append(conn.sent, probe)
	conn.mu.Unlock()

	if conn.onSend != nil {
		conn.onSend(probe)
	}

	return len(data), nil
}

func (conn *fakePacketConn) Close() error                     { return nil }
func (conn *fakePacketConn) LocalAddr() net.Addr              { return nil }
func (conn *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (conn *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (conn *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

// attempts returns how many writes were tried, failed ones included.
func (conn *fakePacketConn) attempts() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	return conn.count
}

func (conn *fakePacketConn) sentProbes() []*sentProbe {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	return append([]*sentProbe(nil), conn.sent...)
}

// resultCollector gathers results from the callback.
type resultCollector struct {
	mu      sync.Mutex
	results []*Result
}

func (collector *resultCollector) callback(result *Result) {
	collector.mu.Lock()
	defer collector.mu.Unlock()

	collector.results = append(collector.results, result)
}

func (collector *resultCollector) all() []*Result {
	collector.mu.Lock()
	defer collector.mu.Unlock()

	return append([]*Result(nil), collector.results...)
}

// fixedSourceIp is a SourceIpResolver that always answers with the same address.
func fixedSourceIp(ip string) SourceIpResolver {
	return func(destination net.IP) (net.IP, error) {
		if destination.To4() != nil {
			return net.ParseIP(ip).To4(), nil
		}
		return net.ParseIP("2001:db8::ffff"), nil
	}
}
