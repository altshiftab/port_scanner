package port_scanner

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/altshiftab/utils_go/pkg/net/packet"
)

// packetSpec describes a packet to build for a test.
type packetSpec struct {
	// ipv6DestinationOptions inserts a Destination Options extension header between the IPv6
	// header and the transport header.
	ipv6DestinationOptions bool
	// laterFragment marks the packet as a fragment other than the first.
	laterFragment bool
	sourceIp      string
	destinationIp string
	sourcePort    uint16
	destPort      uint16
	seq           uint32
	ack           uint32
	syn           bool
	ackFlag       bool
	rst           bool
	udp           bool
	payload       []byte
}

// buildPacket serializes the described packet from its IP header on, as a capture handle delivers
// it.
func buildPacket(t *testing.T, spec *packetSpec) []byte {
	t.Helper()

	source, err := netip.ParseAddr(spec.sourceIp)
	if err != nil {
		t.Fatalf("parse source address: %v", err)
	}
	destination, err := netip.ParseAddr(spec.destinationIp)
	if err != nil {
		t.Fatalf("parse destination address: %v", err)
	}

	var transport []byte
	protocol := packet.ProtocolTcp
	if spec.udp {
		// Source port, destination port, length and a zero (absent) checksum.
		protocol = packet.ProtocolUdp
		transport = binary.BigEndian.AppendUint16(nil, spec.sourcePort)
		transport = binary.BigEndian.AppendUint16(transport, spec.destPort)
		transport = binary.BigEndian.AppendUint16(transport, uint16(8+len(spec.payload))) //nolint:gosec // Test payloads are small.
		transport = append(transport, 0, 0)
		transport = append(transport, spec.payload...)
	} else {
		var flags packet.TcpFlags
		if spec.syn {
			flags |= packet.TcpFlagSyn
		}
		if spec.ackFlag {
			flags |= packet.TcpFlagAck
		}
		if spec.rst {
			flags |= packet.TcpFlagRst
		}

		transport, err = packet.AppendTcp(nil, &packet.Tcp{
			SourcePort:      spec.sourcePort,
			DestinationPort: spec.destPort,
			Sequence:        spec.seq,
			Acknowledgement: spec.ack,
			Flags:           flags,
			Window:          65535,
			Payload:         spec.payload,
		}, source, destination)
		if err != nil {
			t.Fatalf("append tcp: %v", err)
		}
	}

	ip := &packet.Ip{Source: source, Destination: destination, Protocol: protocol, Payload: transport}
	if source.Is4() {
		ip.Version = 4
		if spec.laterFragment {
			ip.FragmentOffset = 1480
		}
	} else {
		ip.Version = 6
		if spec.ipv6DestinationOptions {
			// Next header, length 0 (eight bytes), and a PadN option filling the rest.
			ip.Payload = append([]byte{protocol, 0, 1, 4, 0, 0, 0, 0}, transport...)
			ip.Protocol = packet.ProtocolIpv6DestinationOptions
		}
		if spec.laterFragment {
			// Next header, reserved, offset 185 eight-byte units, identification.
			ip.Payload = append([]byte{ip.Protocol, 0, 0x05, 0xc8, 0, 0, 0, 1}, ip.Payload...)
			ip.Protocol = packet.ProtocolIpv6Fragment
		}
	}

	data, err := packet.AppendIp(nil, ip)
	if err != nil {
		t.Fatalf("append ip: %v", err)
	}

	return data
}

// fakePacketSource hands out queued packets and behaves like an idle capture handle otherwise: a
// read blocks until a packet is queued or the source is closed, after which reads report EOF.
//
// It does not give up on its own. A source that reported itself done after a quiet spell would
// end its reader mid-scan whenever the sender was slow to send the next probe -- under the race
// detector, routinely -- and the replies that followed would go unheard.
type fakePacketSource struct {
	closed  atomic.Bool
	packets chan []byte
	done    chan struct{}
	once    sync.Once
}

func newFakePacketSource() *fakePacketSource {
	return &fakePacketSource{
		packets: make(chan []byte, 1024),
		done:    make(chan struct{}),
	}
}

func (source *fakePacketSource) Closed() bool { return source.closed.Load() }

func (source *fakePacketSource) ReadPacketData() ([]byte, error) {
	select {
	case <-source.done:
		return nil, io.EOF
	case data := <-source.packets:
		return data, nil
	}
}

func (source *fakePacketSource) inject(data []byte) {
	source.packets <- data
}

func (source *fakePacketSource) close() {
	source.once.Do(func() {
		source.closed.Store(true)
		close(source.done)
	})
}

var errNotAnIpAddress = errors.New("address is not an ip address")

// sentProbe is a probe as a fakePacketConn saw it: the segment decoded, and where it went.
type sentProbe struct {
	destination net.IP
	tcp         *packet.Tcp
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

	tcp, err := packet.ParseTcp(slices.Clone(data))
	if err != nil {
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
