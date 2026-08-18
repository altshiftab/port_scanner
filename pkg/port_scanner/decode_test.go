package port_scanner

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func TestReplyDecoderDecode(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		spec         packetSpec
		linkType     layers.LinkType
		wantReply    bool
		wantSourceIp string
		wantVersion  int
	}{
		{
			name: "ethernet ipv4 syn/ack",
			spec: packetSpec{
				linkType: layers.LinkTypeEthernet, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 80, destPort: 40000, seq: 1000, ack: 12346, syn: true, ackFlag: true,
			},
			linkType:     layers.LinkTypeEthernet,
			wantReply:    true,
			wantSourceIp: "192.0.2.10",
			wantVersion:  4,
		},
		{
			name: "ethernet ipv6 syn/ack",
			spec: packetSpec{
				linkType: layers.LinkTypeEthernet, sourceIp: "2001:db8::10", destinationIp: "2001:db8::1",
				sourcePort: 443, destPort: 40000, seq: 1, ack: 2, syn: true, ackFlag: true,
			},
			linkType:     layers.LinkTypeEthernet,
			wantReply:    true,
			wantSourceIp: "2001:db8::10",
			wantVersion:  6,
		},
		{
			name: "vlan tagged syn/ack",
			spec: packetSpec{
				linkType: layers.LinkTypeEthernet, vlan: true, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 80, destPort: 40000, seq: 1000, ack: 12346, syn: true, ackFlag: true,
			},
			linkType:     layers.LinkTypeEthernet,
			wantReply:    true,
			wantSourceIp: "192.0.2.10",
			wantVersion:  4,
		},
		{
			name: "raw ipv4 syn/ack on a tunnel",
			spec: packetSpec{
				linkType: linkTypeDltRaw, sourceIp: "10.8.0.1", destinationIp: "10.8.0.2",
				sourcePort: 22, destPort: 40000, seq: 5, ack: 6, syn: true, ackFlag: true,
			},
			linkType:     linkTypeDltRaw,
			wantReply:    true,
			wantSourceIp: "10.8.0.1",
			wantVersion:  4,
		},
		{
			name: "raw ipv6 syn/ack on a tunnel",
			spec: packetSpec{
				linkType: layers.LinkTypeRaw, sourceIp: "fd00::1", destinationIp: "fd00::2",
				sourcePort: 22, destPort: 40000, seq: 5, ack: 6, syn: true, ackFlag: true,
			},
			linkType:     layers.LinkTypeRaw,
			wantReply:    true,
			wantSourceIp: "fd00::1",
			wantVersion:  6,
		},
		{
			name: "linux cooked capture syn/ack",
			spec: packetSpec{
				linkType: layers.LinkTypeLinuxSLL, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 80, destPort: 40000, seq: 1000, ack: 12346, syn: true, ackFlag: true,
			},
			linkType:     layers.LinkTypeLinuxSLL,
			wantReply:    true,
			wantSourceIp: "192.0.2.10",
			wantVersion:  4,
		},
		{
			name: "linux cooked capture v2 syn/ack",
			spec: packetSpec{
				linkType: layers.LinkTypeLinuxSLL2, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 80, destPort: 40000, seq: 1000, ack: 12346, syn: true, ackFlag: true,
			},
			linkType:     layers.LinkTypeLinuxSLL2,
			wantReply:    true,
			wantSourceIp: "192.0.2.10",
			wantVersion:  4,
		},
		{
			name: "ipv6 syn/ack behind a destination options header",
			spec: packetSpec{
				linkType: layers.LinkTypeEthernet, ipv6DestinationOptions: true,
				sourceIp: "2001:db8::10", destinationIp: "2001:db8::1",
				sourcePort: 443, destPort: 40000, seq: 1, ack: 2, syn: true, ackFlag: true,
			},
			linkType:     layers.LinkTypeEthernet,
			wantReply:    true,
			wantSourceIp: "2001:db8::10",
			wantVersion:  6,
		},
		{
			name: "unknown link type falls back to ethernet",
			spec: packetSpec{
				linkType: layers.LinkTypeEthernet, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 80, destPort: 40000, seq: 1000, ack: 12346, syn: true, ackFlag: true,
			},
			linkType:     layers.LinkTypeFDDI,
			wantReply:    true,
			wantSourceIp: "192.0.2.10",
			wantVersion:  4,
		},
		{
			name: "unknown link type falls back to raw ip",
			spec: packetSpec{
				linkType: linkTypeDltRaw, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 80, destPort: 40000, seq: 1000, ack: 12346, syn: true, ackFlag: true,
			},
			linkType:     layers.LinkTypeFDDI,
			wantReply:    true,
			wantSourceIp: "192.0.2.10",
			wantVersion:  4,
		},
		{
			name: "syn/ack with data is still a reply",
			spec: packetSpec{
				linkType: layers.LinkTypeEthernet, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 443, destPort: 40000, seq: 1000, ack: 12346, syn: true, ackFlag: true,
				payload: []byte{0x16, 0x03, 0x01},
			},
			linkType:     layers.LinkTypeEthernet,
			wantReply:    true,
			wantSourceIp: "192.0.2.10",
			wantVersion:  4,
		},
		{
			name: "rst/ack is not a reply",
			spec: packetSpec{
				linkType: layers.LinkTypeEthernet, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 81, destPort: 40000, seq: 0, ack: 12346, rst: true, ackFlag: true,
			},
			linkType: layers.LinkTypeEthernet,
		},
		{
			name: "plain syn is not a reply",
			spec: packetSpec{
				linkType: layers.LinkTypeEthernet, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 5555, destPort: 40000, seq: 0, syn: true,
			},
			linkType: layers.LinkTypeEthernet,
		},
		{
			name: "plain ack is not a reply",
			spec: packetSpec{
				linkType: layers.LinkTypeEthernet, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 5555, destPort: 40000, seq: 0, ack: 1, ackFlag: true,
			},
			linkType: layers.LinkTypeEthernet,
		},
		{
			name: "udp is not a reply",
			spec: packetSpec{
				linkType: layers.LinkTypeEthernet, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 53, destPort: 40000, udp: true,
			},
			linkType: layers.LinkTypeEthernet,
		},
		{
			name: "raw framing on an ethernet handle is not decoded",
			spec: packetSpec{
				linkType: linkTypeDltRaw, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
				sourcePort: 80, destPort: 40000, seq: 1000, ack: 12346, syn: true, ackFlag: true,
			},
			linkType: layers.LinkTypeEthernet,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			decoder := newReplyDecoder(testCase.linkType)
			data := buildPacket(t, &testCase.spec)

			reply, ok := decoder.decode(data)
			if ok != testCase.wantReply {
				t.Fatalf("decode() ok = %v, want %v (reply %+v)", ok, testCase.wantReply, reply)
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

func TestReplyDecoderRejectsGarbage(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		linkType layers.LinkType
		data     []byte
	}{
		{name: "empty ethernet", linkType: layers.LinkTypeEthernet, data: nil},
		{name: "empty raw", linkType: linkTypeDltRaw, data: nil},
		{name: "short ethernet", linkType: layers.LinkTypeEthernet, data: []byte{1, 2, 3}},
		{name: "raw with bad version", linkType: linkTypeDltRaw, data: []byte{0x95, 0, 0, 0}},
		{name: "truncated ipv4", linkType: linkTypeDltRaw, data: []byte{0x45, 0, 0, 40, 0, 0}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			decoder := newReplyDecoder(testCase.linkType)
			if reply, ok := decoder.decode(testCase.data); ok {
				t.Fatalf("decode() = %+v, want no reply", reply)
			}
		})
	}
}

func TestReplyDecoderCopiesAddresses(t *testing.T) {
	t.Parallel()

	decoder := newReplyDecoder(layers.LinkTypeEthernet)

	first, ok := decoder.decode(buildPacket(t, &packetSpec{
		linkType: layers.LinkTypeEthernet, sourceIp: "192.0.2.10", destinationIp: "192.0.2.1",
		sourcePort: 80, destPort: 40000, seq: 1, ack: 2, syn: true, ackFlag: true,
	}))
	if !ok {
		t.Fatalf("first decode failed")
	}

	if _, ok := decoder.decode(buildPacket(t, &packetSpec{
		linkType: layers.LinkTypeEthernet, sourceIp: "192.0.2.20", destinationIp: "192.0.2.1",
		sourcePort: 81, destPort: 40000, seq: 1, ack: 2, syn: true, ackFlag: true,
	})); !ok {
		t.Fatalf("second decode failed")
	}

	if first.sourceIp.String() != "192.0.2.10" || first.sourcePort != 80 {
		t.Fatalf("first reply changed after the second decode: %+v", first)
	}
}
