package port_scanner

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"net"
	"slices"
	"sort"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
)

const (
	// maxHostBits caps the size of a single network so that its address count, times the port
	// count, fits the arithmetic below. 2^62 addresses is far beyond anything a scan completes.
	maxHostBits = 62
	// maxPort is the largest TCP port number.
	maxPort = math.MaxUint16
)

// targetSpace enumerates the (address, port) pairs of a scan: every address of every network,
// combined with every port. Pairs are numbered from 0, network by network, and within a network
// address-major, so that pair i of network k is address i / len(ports) with port i % len(ports).
type targetSpace struct {
	networks []*net.IPNet
	ports    []int
	// cumulativeCounts[k] is the number of pairs in networks 0..k, so that a pair's network is
	// found by binary search.
	cumulativeCounts []uint64
}

// newTargetSpace validates the networks and ports and lays out the target space. Ports are
// deduplicated and sorted; the order in which targets are visited is decided elsewhere.
func newTargetSpace(networks []*net.IPNet, ports []int) (*targetSpace, error) {
	if len(networks) == 0 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("networks")),
		)
	}

	if len(ports) == 0 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("ports")),
		)
	}

	for _, port := range ports {
		if port < 1 || port > maxPort {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: %w: %d", altshiftErrors.ErrValidationError, portScannerErrors.ErrInvalidPort, port),
				port,
			)
		}
	}

	uniquePorts := slices.Clone(ports)
	slices.Sort(uniquePorts)
	uniquePorts = slices.Compact(uniquePorts)

	space := &targetSpace{
		networks:         make([]*net.IPNet, 0, len(networks)),
		ports:            uniquePorts,
		cumulativeCounts: make([]uint64, 0, len(networks)),
	}

	var total uint64
	for i, network := range networks {
		if network == nil {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, nil_error.New("network")),
				i,
			)
		}

		normalized, hostBits, err := normalizeNetwork(network)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("normalize network: %w", err), network)
		}

		count, ok := multiply(uint64(1)<<hostBits, uint64(len(uniquePorts)))
		if !ok {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, portScannerErrors.ErrTooManyTargets),
				network,
			)
		}

		total, ok = add(total, count)
		if !ok {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, portScannerErrors.ErrTooManyTargets),
				network,
			)
		}

		space.networks = append(space.networks, normalized)
		space.cumulativeCounts = append(space.cumulativeCounts, total)
	}

	return space, nil
}

// multiply returns a×b and whether it fit in an int64-sized range.
func multiply(a, b uint64) (uint64, bool) {
	hi, lo := bits.Mul64(a, b)
	return lo, hi == 0 && lo <= math.MaxInt64
}

// add returns a+b and whether it fit in an int64-sized range.
func add(a, b uint64) (uint64, bool) {
	sum, carry := bits.Add64(a, b, 0)
	return sum, carry == 0 && sum <= math.MaxInt64
}

// normalizeNetwork returns the network with its address masked and, for IPv4, in four-byte form,
// together with the number of host bits its mask leaves. Masks that are not canonical, or that
// leave more host bits than a scan can address, are rejected.
func normalizeNetwork(network *net.IPNet) (*net.IPNet, int, error) {
	maskOnes, maskBits := network.Mask.Size()
	if maskBits == 0 {
		return nil, 0, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, portScannerErrors.ErrInvalidNetworkMask),
			network,
		)
	}

	ip := network.IP
	switch maskBits {
	case net.IPv4len * 8:
		ip = ip.To4()
	case net.IPv6len * 8:
		ip = ip.To16()
	default:
		return nil, 0, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, portScannerErrors.ErrInvalidNetworkMask),
			network,
		)
	}
	if ip == nil {
		return nil, 0, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, portScannerErrors.ErrInvalidNetworkMask),
			network,
		)
	}

	hostBits := maskBits - maskOnes
	if hostBits > maxHostBits {
		return nil, 0, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, portScannerErrors.ErrTooManyTargets),
			network,
		)
	}

	return &net.IPNet{IP: ip.Mask(network.Mask), Mask: network.Mask}, hostBits, nil
}

// Size returns the number of (address, port) pairs.
func (space *targetSpace) Size() uint64 {
	if len(space.cumulativeCounts) == 0 {
		return 0
	}

	return space.cumulativeCounts[len(space.cumulativeCounts)-1]
}

// Target returns the address and port of pair number index, and the index of the network the
// address belongs to.
func (space *targetSpace) Target(index uint64) (net.IP, int, int, error) {
	networkIndex := sort.Search(len(space.cumulativeCounts), func(i int) bool {
		return space.cumulativeCounts[i] > index
	})
	if networkIndex >= len(space.networks) {
		return nil, 0, 0, altshiftErrors.NewWithTrace(portScannerErrors.ErrIndexOutsideRange, index)
	}

	offset := index
	if networkIndex > 0 {
		offset -= space.cumulativeCounts[networkIndex-1]
	}

	numPorts := uint64(len(space.ports))
	addressOffset, portOffset := offset/numPorts, offset%numPorts

	ip, err := nthAddress(space.networks[networkIndex], addressOffset)
	if err != nil {
		return nil, 0, 0, altshiftErrors.New(fmt.Errorf("nth address: %w", err), space.networks[networkIndex], addressOffset)
	}

	return ip, space.ports[portOffset], networkIndex, nil
}

// nthAddress returns the address n places after the network's first address. The network must have
// been normalized: its address masked and of the length its mask implies.
func nthAddress(network *net.IPNet, n uint64) (net.IP, error) {
	if network == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("network"))
	}

	switch len(network.IP) {
	case net.IPv4len:
		base := uint64(binary.BigEndian.Uint32(network.IP))
		sum := base + n
		if sum > math.MaxUint32 {
			return nil, altshiftErrors.NewWithTrace(portScannerErrors.ErrIndexOutsideRange, network, n)
		}

		ip := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(ip, uint32(sum))

		return ip, nil
	case net.IPv6len:
		high := binary.BigEndian.Uint64(network.IP[:8])
		low := binary.BigEndian.Uint64(network.IP[8:])

		low, carry := bits.Add64(low, n, 0)
		high, carry = bits.Add64(high, 0, carry)
		if carry != 0 {
			return nil, altshiftErrors.NewWithTrace(portScannerErrors.ErrIndexOutsideRange, network, n)
		}

		ip := make(net.IP, net.IPv6len)
		binary.BigEndian.PutUint64(ip[:8], high)
		binary.BigEndian.PutUint64(ip[8:], low)

		return ip, nil
	default:
		return nil, altshiftErrors.NewWithTrace(portScannerErrors.ErrInvalidNetworkMask, network)
	}
}
