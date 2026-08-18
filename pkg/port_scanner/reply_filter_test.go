package port_scanner

import (
	"encoding/binary"
	"slices"
	"testing"

	"golang.org/x/net/bpf"
)

const replyFilterTestPort = 44444

// frame builds an Ethernet frame carrying the given payload.
func frame(etherType uint16, payload []byte) []byte {
	out := make([]byte, etherHeaderSize)
	binary.BigEndian.PutUint16(out[etherTypeOffset:], etherType)
	return slices.Concat(out, payload)
}

// ipv4Packet builds an IPv4 packet with the given protocol, fragment offset and
// payload, using a header of headerWords 32-bit words.
func ipv4Packet(protocol byte, fragmentOffset uint16, headerWords byte, payload []byte) []byte {
	header := make([]byte, int(headerWords)*4)
	header[0] = 0x40 | headerWords // version 4, IHL
	binary.BigEndian.PutUint16(header[6:], fragmentOffset)
	header[9] = protocol
	return slices.Concat(header, payload)
}

// ipv6Packet builds an IPv6 packet with the given next header and payload.
func ipv6Packet(nextHeader byte, payload []byte) []byte {
	header := make([]byte, ipv6HeaderSize)
	header[0] = 0x60
	header[6] = nextHeader
	return slices.Concat(header, payload)
}

// tcpSegment builds a TCP segment addressed to destinationPort.
func tcpSegment(destinationPort uint16) []byte {
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment[0:], 12345)
	binary.BigEndian.PutUint16(segment[tcpDestinationPortOffset:], destinationPort)
	return segment
}

// The filter decides what the scanner ever sees. A mistake here does not fail
// loudly - it silently drops replies and the scan reports nothing open - so the
// program is run against crafted frames rather than trusted by inspection.
func TestReplyFilterAcceptsAndRejects(t *testing.T) {
	t.Parallel()

	rawInstructions, err := ReplyFilter(replyFilterTestPort)
	if err != nil {
		t.Fatalf("ReplyFilter: %v", err)
	}

	vm, err := bpf.NewVM(mustParse(t, rawInstructions))
	if err != nil {
		t.Fatalf("bpf.NewVM: %v", err)
	}

	testCases := []struct {
		name       string
		frame      []byte
		wantAccept bool
	}{
		{
			name:       "ipv4 tcp addressed to the listen port",
			frame:      frame(etherTypeIpv4, ipv4Packet(protocolTcp, 0, 5, tcpSegment(replyFilterTestPort))),
			wantAccept: true,
		},
		{
			name:       "ipv4 tcp addressed elsewhere",
			frame:      frame(etherTypeIpv4, ipv4Packet(protocolTcp, 0, 5, tcpSegment(80))),
			wantAccept: false,
		},
		{
			name:       "ipv4 udp to the listen port",
			frame:      frame(etherTypeIpv4, ipv4Packet(17, 0, 5, tcpSegment(replyFilterTestPort))),
			wantAccept: false,
		},
		{
			// A header with options is longer, so the port offset must be
			// computed from the IHL rather than assumed.
			name:       "ipv4 tcp with header options",
			frame:      frame(etherTypeIpv4, ipv4Packet(protocolTcp, 0, 8, tcpSegment(replyFilterTestPort))),
			wantAccept: true,
		},
		{
			// A later fragment has no TCP header, so whatever sits at the port
			// offset is not a port.
			name:       "ipv4 non-first fragment",
			frame:      frame(etherTypeIpv4, ipv4Packet(protocolTcp, 100, 5, tcpSegment(replyFilterTestPort))),
			wantAccept: false,
		},
		{
			name:       "ipv6 tcp addressed to the listen port",
			frame:      frame(etherTypeIpv6, ipv6Packet(protocolTcp, tcpSegment(replyFilterTestPort))),
			wantAccept: true,
		},
		{
			name:       "ipv6 tcp addressed elsewhere",
			frame:      frame(etherTypeIpv6, ipv6Packet(protocolTcp, tcpSegment(443))),
			wantAccept: false,
		},
		{
			name:       "ipv6 udp to the listen port",
			frame:      frame(etherTypeIpv6, ipv6Packet(17, tcpSegment(replyFilterTestPort))),
			wantAccept: false,
		},
		{
			name:       "arp is not ip at all",
			frame:      frame(0x0806, make([]byte, 28)),
			wantAccept: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			accepted, err := vm.Run(testCase.frame)
			if err != nil {
				t.Fatalf("vm.Run: %v", err)
			}

			if (accepted > 0) != testCase.wantAccept {
				t.Errorf("accepted = %d (want accept = %v)", accepted, testCase.wantAccept)
			}
		})
	}
}

func TestReplyFilterAssembles(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		port int
	}{
		{name: "low port", port: 1},
		{name: "typical ephemeral port", port: 44444},
		{name: "highest port", port: 65535},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			rawInstructions, err := ReplyFilter(testCase.port)
			if err != nil {
				t.Fatalf("ReplyFilter: %v", err)
			}
			if len(rawInstructions) == 0 {
				t.Fatal("assembled to an empty program")
			}
		})
	}
}

// mustParse turns the raw program back into instructions, which is what the VM
// takes; a program that will not round-trip would not load into a socket either.
func mustParse(t *testing.T, rawInstructions []bpf.RawInstruction) []bpf.Instruction {
	t.Helper()

	instructions, allDecoded := bpf.Disassemble(rawInstructions)
	if !allDecoded {
		t.Fatal("assembled program did not fully disassemble")
	}

	return instructions
}
