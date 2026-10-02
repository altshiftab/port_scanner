package port_scanner

import (
	"testing"
)

func TestDecodeReply(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		spec         packetSpec
		wantReply    bool
		wantSourceIp string
		wantVersion  int
	}{
		{
			name: "ipv4 syn/ack",
			spec: packetSpec{
				sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 80, destPort: 40000, seq: 1000, ack: 12346, syn: true, ackFlag: true,
			},
			wantReply:    true,
			wantSourceIp: "192.0.2.10",
			wantVersion:  4,
		},
		{
			name: "ipv6 syn/ack",
			spec: packetSpec{
				sourceIp: "2001:db8::10", destinationIp: "2001:db8::1",
				sourcePort: 443, destPort: 40000, seq: 1, ack: 2, syn: true, ackFlag: true,
			},
			wantReply:    true,
			wantSourceIp: "2001:db8::10",
			wantVersion:  6,
		},
		{
			name: "ipv6 syn/ack behind a destination options header",
			spec: packetSpec{
				ipv6DestinationOptions: true,
				sourceIp:               "2001:db8::10", destinationIp: "2001:db8::1",
				sourcePort: 443, destPort: 40000, seq: 1, ack: 2, syn: true, ackFlag: true,
			},
			wantReply:    true,
			wantSourceIp: "2001:db8::10",
			wantVersion:  6,
		},
		{
			name: "syn/ack with data is still a reply",
			spec: packetSpec{
				sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 443, destPort: 40000, seq: 1000, ack: 12346, syn: true, ackFlag: true,
				payload: []byte{0x16, 0x03, 0x01},
			},
			wantReply:    true,
			wantSourceIp: "192.0.2.10",
			wantVersion:  4,
		},
		{
			name: "rst/ack is not a reply",
			spec: packetSpec{
				sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 81, destPort: 40000, seq: 0, ack: 12346, rst: true, ackFlag: true,
			},
		},
		{
			name: "syn/ack/rst is not a reply",
			spec: packetSpec{
				sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 81, destPort: 40000, seq: 0, ack: 12346, syn: true, rst: true, ackFlag: true,
			},
		},
		{
			name: "plain syn is not a reply",
			spec: packetSpec{
				sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 5555, destPort: 40000, seq: 0, syn: true,
			},
		},
		{
			name: "plain ack is not a reply",
			spec: packetSpec{
				sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 5555, destPort: 40000, seq: 0, ack: 1, ackFlag: true,
			},
		},
		{
			name: "udp is not a reply",
			spec: packetSpec{
				sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 53, destPort: 40000, udp: true,
			},
		},
		{
			name: "an ipv4 fragment is not a reply",
			spec: packetSpec{
				laterFragment: true, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 80, destPort: 40000, seq: 1000, ack: 12346, syn: true, ackFlag: true,
			},
		},
		{
			name: "an ipv6 fragment is not a reply",
			spec: packetSpec{
				laterFragment: true, sourceIp: "2001:db8::10", destinationIp: "2001:db8::1",
				sourcePort: 443, destPort: 40000, seq: 1, ack: 2, syn: true, ackFlag: true,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			reply, ok := decodeReply(buildPacket(t, &testCase.spec))
			if ok != testCase.wantReply {
				t.Fatalf("decodeReply() ok = %v, want %v (reply %+v)", ok, testCase.wantReply, reply)
			}
			if !ok {
				return
			}

			if reply.sourceIp.String() != testCase.wantSourceIp {
				t.Errorf("sourceIp = %v, want %v", reply.sourceIp, testCase.wantSourceIp)
			}
			if reply.destinationIp.String() != testCase.spec.destinationIp {
				t.Errorf("destinationIp = %v, want %v", reply.destinationIp, testCase.spec.destinationIp)
			}
			if reply.sourcePort != int(testCase.spec.sourcePort) {
				t.Errorf("sourcePort = %d, want %d", reply.sourcePort, testCase.spec.sourcePort)
			}
			if reply.destinationPort != int(testCase.spec.destPort) {
				t.Errorf("destinationPort = %d, want %d", reply.destinationPort, testCase.spec.destPort)
			}
			if reply.ackNumber != testCase.spec.ack {
				t.Errorf("ackNumber = %d, want %d", reply.ackNumber, testCase.spec.ack)
			}
			if reply.ipVersion != testCase.wantVersion {
				t.Errorf("ipVersion = %d, want %d", reply.ipVersion, testCase.wantVersion)
			}
		})
	}
}

func TestDecodeReplyRejectsGarbage(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "short", data: []byte{1, 2, 3}},
		{name: "bad version", data: []byte{0x95, 0, 0, 0}},
		{name: "truncated ipv4", data: []byte{0x45, 0, 0, 40, 0, 0}},
		// An Ethernet frame: what a capture would hand over if the socket kept link-layer headers.
		{name: "an ethernet frame", data: append([]byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00}, make([]byte, 40)...)},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if reply, ok := decodeReply(testCase.data); ok {
				t.Fatalf("decodeReply() = %+v, want no reply", reply)
			}
		})
	}
}
