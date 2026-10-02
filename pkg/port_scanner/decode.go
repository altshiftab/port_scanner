package port_scanner

import (
	"net/netip"

	"github.com/altshiftab/utils_go/pkg/net/packet"
)

const (
	ipv4Version = 4
	ipv6Version = 6
)

// reply is what a captured packet contributes to a scan: the endpoints and the acknowledgement
// number of a SYN/ACK.
type reply struct {
	sourceIp        netip.Addr
	destinationIp   netip.Addr
	sourcePort      int
	destinationPort int
	ackNumber       uint32
	ipVersion       int
}

// decodeReply extracts the reply from a captured packet, which starts at its IP header. It reports
// false for anything that is not a TCP SYN/ACK, including packets it cannot decode and fragments,
// whose TCP header is either elsewhere or not to be trusted alone.
func decodeReply(data []byte) (*reply, bool) {
	ip, err := packet.ParseIp(data)
	if err != nil || ip.Protocol != packet.ProtocolTcp || ip.Fragmented() {
		return nil, false
	}

	tcp, err := packet.ParseTcp(ip.Payload)
	if err != nil {
		return nil, false
	}

	// Only the first thing an open port says is of interest: the SYN/ACK. Everything else a port
	// may send to the listen port, RSTs above all, is not.
	if !tcp.Flags.Has(packet.TcpFlagSyn|packet.TcpFlagAck) || tcp.Flags.Has(packet.TcpFlagRst) {
		return nil, false
	}

	return &reply{
		sourceIp:        ip.Source,
		destinationIp:   ip.Destination,
		sourcePort:      int(tcp.SourcePort),
		destinationPort: int(tcp.DestinationPort),
		ackNumber:       tcp.Acknowledgement,
		ipVersion:       ip.Version,
	}, true
}
