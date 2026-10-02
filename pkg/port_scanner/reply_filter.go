package port_scanner

import (
	"fmt"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"golang.org/x/net/bpf"
)

// Offsets into a captured packet that the reply filter reads. The capture socket hands over each
// packet from its IP header on, whatever the link it arrived over, so the offsets are counted from
// there.
const (
	// The IP version is the high nibble of the first byte, in both versions.
	ipVersionOffset = 0
	ipVersionMask   = 0xf0

	ipv4ProtocolOffset       = 9
	ipv4FragmentOffsetOffset = 6
	ipv4HeaderLengthOffset   = 0

	// IPv6 has a fixed 40-byte header, so the payload sits at a known offset.
	ipv6NextHeaderOffset = 6
	ipv6HeaderSize       = 40
)

const (
	ipv4VersionNibble = 0x40
	ipv6VersionNibble = 0x60

	protocolTcp = 6

	// fragmentOffsetMask covers the fragment-offset bits of the IPv4 flags and
	// offset field. A non-zero offset means the segment header is in an earlier
	// fragment, so there are no ports to read here.
	fragmentOffsetMask = 0x1fff

	// tcpDestinationPortOffset is where the destination port sits within a TCP
	// header.
	tcpDestinationPortOffset = 2
)

// snapshotLength is how much of an accepted frame to keep. A reply that matters
// is a bare TCP segment, so the headers are all that is ever read.
const snapshotLength = 262144

// ReplyFilterInstructions returns the filter program that keeps only what could
// be a reply to a probe sent from listenPort: a TCP segment addressed to that
// port, over IPv4 or IPv6.
//
// The program is written out rather than compiled from a filter string because
// compiling a string is what libpcap is for, and this package no longer links
// it. Assembling it here keeps the capture path free of cgo.
func ReplyFilterInstructions(listenPort uint16) []bpf.Instruction {
	port := uint32(listenPort)

	return []bpf.Instruction{
		// Dispatch on the IP version. The socket also sees what is not IP, ARP above all; such a
		// packet that happens to start with one of these nibbles still has to pass the checks
		// below, and the reader drops it by its link-layer protocol regardless.
		bpf.LoadAbsolute{Off: ipVersionOffset, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: ipVersionMask},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipv4VersionNibble, SkipTrue: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipv6VersionNibble, SkipTrue: 7, SkipFalse: 12},

		// IPv4: the header is variable length, so the port offset is computed.
		bpf.LoadAbsolute{Off: ipv4ProtocolOffset, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protocolTcp, SkipTrue: 10},
		// A fragment after the first carries no TCP header to read.
		bpf.LoadAbsolute{Off: ipv4FragmentOffsetOffset, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: fragmentOffsetMask, SkipTrue: 8},
		bpf.LoadMemShift{Off: ipv4HeaderLengthOffset},
		bpf.LoadIndirect{Off: tcpDestinationPortOffset, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: port, SkipTrue: 4, SkipFalse: 5},

		// IPv6: a fixed-length header, so the port offset is a constant. Only a
		// bare TCP next header is accepted; a packet carrying extension headers
		// is not a reply this scanner sends probes to provoke.
		bpf.LoadAbsolute{Off: ipv6NextHeaderOffset, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protocolTcp, SkipTrue: 3},
		bpf.LoadAbsolute{Off: ipv6HeaderSize + tcpDestinationPortOffset, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: port, SkipTrue: 1},

		bpf.RetConstant{Val: snapshotLength},
		bpf.RetConstant{Val: 0},
	}
}

// ReplyFilter assembles the reply filter for listenPort into the raw form a
// capture handle takes.
func ReplyFilter(listenPort int) ([]bpf.RawInstruction, error) {
	if listenPort < 1 || listenPort > maxPort {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, portScannerErrors.ErrPortOutOfRange),
			listenPort,
		)
	}

	rawInstructions, err := bpf.Assemble(ReplyFilterInstructions(uint16(listenPort)))
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("bpf assemble: %w", err), listenPort)
	}

	return rawInstructions, nil
}
