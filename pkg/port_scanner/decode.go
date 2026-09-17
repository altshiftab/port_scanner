package port_scanner

import (
	"net"
	"slices"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// linkTypeDltRaw is DLT_RAW, the link type of an interface that carries bare IP packets rather than
// frames -- a tunnel, most often. gopacket's LinkTypeRaw is the pcap-file value for the same thing
// (101) and this is the DLT value, so both are recognised.
const linkTypeDltRaw layers.LinkType = 12

const (
	ipv4Version = 4
	ipv6Version = 6
)

// reply is what a captured packet contributes to a scan: the endpoints and the acknowledgement
// number of a SYN/ACK.
type reply struct {
	sourceIp        net.IP
	destinationIp   net.IP
	sourcePort      int
	destinationPort int
	ackNumber       uint32
	ipVersion       int
}

// replyDecoder decodes captured packets of one link type into replies. It holds decoding state and
// so serves one reader at a time.
type replyDecoder struct {
	linkType layers.LinkType

	eth           layers.Ethernet
	dot1q         layers.Dot1Q
	sll           layers.LinuxSLL
	sll2          layers.LinuxSLL2
	ip4           layers.IPv4
	ip6           layers.IPv6
	ip6Extensions layers.IPv6ExtensionSkipper
	tcp           layers.TCP

	decoded []gopacket.LayerType

	ethernetParser *gopacket.DecodingLayerParser
	sllParser      *gopacket.DecodingLayerParser
	sll2Parser     *gopacket.DecodingLayerParser
	ipv4Parser     *gopacket.DecodingLayerParser
	ipv6Parser     *gopacket.DecodingLayerParser
}

func newReplyDecoder(linkType layers.LinkType) *replyDecoder {
	decoder := &replyDecoder{linkType: linkType}

	newParser := func(first gopacket.LayerType) *gopacket.DecodingLayerParser {
		// IPv6 extension headers (routing, fragment, destination options; hop-by-hop is handled
		// by the IPv6 layer itself) are skipped over, so that the TCP header behind them is reached.
		parser := gopacket.NewDecodingLayerParser(
			first,
			&decoder.eth, &decoder.dot1q, &decoder.sll, &decoder.sll2,
			&decoder.ip4, &decoder.ip6, &decoder.ip6Extensions, &decoder.tcp,
		)
		// A reply may carry data (TCP Fast Open) whose application layer no decoder is registered
		// for; that is not a failure to decode the headers.
		parser.IgnoreUnsupported = true

		return parser
	}

	decoder.ethernetParser = newParser(layers.LayerTypeEthernet)
	decoder.sllParser = newParser(layers.LayerTypeLinuxSLL)
	decoder.sll2Parser = newParser(layers.LayerTypeLinuxSLL2)
	decoder.ipv4Parser = newParser(layers.LayerTypeIPv4)
	decoder.ipv6Parser = newParser(layers.LayerTypeIPv6)

	return decoder
}

// rawParser picks the network-layer parser for a bare IP packet by its version nibble.
func (decoder *replyDecoder) rawParser(data []byte) *gopacket.DecodingLayerParser {
	if len(data) == 0 {
		return nil
	}

	switch data[0] >> 4 {
	case ipv4Version:
		return decoder.ipv4Parser
	case ipv6Version:
		return decoder.ipv6Parser
	default:
		return nil
	}
}

// parsers returns the parsers to try for a packet, in order. A link type the decoder knows gets its
// one parser; an unknown one is tried as Ethernet and then as bare IP.
func (decoder *replyDecoder) parsers(data []byte) []*gopacket.DecodingLayerParser {
	switch decoder.linkType {
	case layers.LinkTypeEthernet:
		return []*gopacket.DecodingLayerParser{decoder.ethernetParser}
	case layers.LinkTypeLinuxSLL:
		return []*gopacket.DecodingLayerParser{decoder.sllParser}
	case layers.LinkTypeLinuxSLL2:
		return []*gopacket.DecodingLayerParser{decoder.sll2Parser}
	case linkTypeDltRaw, layers.LinkTypeRaw, layers.LinkTypeIPv4, layers.LinkTypeIPv6:
		if parser := decoder.rawParser(data); parser != nil {
			return []*gopacket.DecodingLayerParser{parser}
		}
		return nil
	default:
		parsers := []*gopacket.DecodingLayerParser{decoder.ethernetParser}
		if parser := decoder.rawParser(data); parser != nil {
			parsers = append(parsers, parser)
		}
		return parsers
	}
}

// decode extracts the reply from a captured packet. It reports false for anything that is not a
// TCP SYN/ACK, including packets it cannot decode.
func (decoder *replyDecoder) decode(data []byte) (*reply, bool) {
	for _, parser := range decoder.parsers(data) {
		if err := parser.DecodeLayers(data, &decoder.decoded); err != nil {
			continue
		}

		if reply, ok := decoder.replyFromDecoded(); ok {
			return reply, true
		}
	}

	return nil, false
}

// replyFromDecoded builds the reply from the layers the last successful decode filled in.
func (decoder *replyDecoder) replyFromDecoded() (*reply, bool) {
	if !slices.Contains(decoder.decoded, layers.LayerTypeTCP) {
		return nil, false
	}

	tcp := &decoder.tcp
	// Only the first thing an open port says is of interest: the SYN/ACK. Everything else a port
	// may send to the listen port, RSTs above all, is not.
	if !tcp.SYN || !tcp.ACK || tcp.RST {
		return nil, false
	}

	var sourceIp, destinationIp net.IP
	var ipVersion int

	switch {
	case slices.Contains(decoder.decoded, layers.LayerTypeIPv4):
		sourceIp, destinationIp, ipVersion = decoder.ip4.SrcIP, decoder.ip4.DstIP, ipv4Version
	case slices.Contains(decoder.decoded, layers.LayerTypeIPv6):
		sourceIp, destinationIp, ipVersion = decoder.ip6.SrcIP, decoder.ip6.DstIP, ipv6Version
	default:
		return nil, false
	}

	if len(sourceIp) == 0 || len(destinationIp) == 0 {
		return nil, false
	}

	// The layer structs are reused for the next packet; the addresses are copied out of them.
	return &reply{
		sourceIp:        slices.Clone(sourceIp),
		destinationIp:   slices.Clone(destinationIp),
		sourcePort:      int(tcp.SrcPort),
		destinationPort: int(tcp.DstPort),
		ackNumber:       tcp.Ack,
		ipVersion:       ipVersion,
	}, true
}
