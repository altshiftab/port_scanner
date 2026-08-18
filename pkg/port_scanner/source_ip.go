package port_scanner

import (
	"fmt"
	"net"
	"sync"
	"syscall"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"golang.org/x/sys/unix"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
)

const (
	// discardPort is the port a UDP socket is connected to when asking the kernel for a route. No
	// datagram is sent, so any port would do; the discard service's is conventional.
	discardPort = 9
	// maxSourceIpCacheSize bounds the source address cache. A scan of a /16 fits entirely; beyond
	// that the kernel is simply asked again, which is correct and only slightly slower.
	maxSourceIpCacheSize = 1 << 16
)

// SourceIpResolver returns the local address the kernel will put on a packet sent to destination.
type SourceIpResolver func(destination net.IP) (net.IP, error)

// KernelSourceIp asks the kernel which local address it would send to destination from, by
// connecting a UDP socket to it and reading the socket's local address. Connecting a UDP socket
// sends nothing; it only makes the kernel perform the same route lookup that a raw-socket send to
// the destination performs, from a socket that is likewise unbound and unmarked, so the answer is
// the source address the probe will carry and the checksum computed over it will be right. The
// two lookups can only part ways under routing policy that keys on the protocol or ports (or
// per-flow multipath across next hops with different preferred sources), which is rare.
func KernelSourceIp(destination net.IP) (net.IP, error) {
	if len(destination) == 0 {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("destination"))
	}

	dialer := net.Dialer{Control: allowBroadcast}
	connection, err := dialer.Dial("udp", net.JoinHostPort(destination.String(), fmt.Sprint(discardPort)))
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("dialer dial: %w", err), destination)
	}
	defer func() { _ = connection.Close() }()

	udpAddr, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w (net udp addr)", altshiftErrors.ErrConversionNotOk),
			connection.LocalAddr(),
		)
	}

	sourceIp := udpAddr.IP
	if len(sourceIp) == 0 {
		return nil, altshiftErrors.NewWithTrace(portScannerErrors.ErrLocalAddressNotResolved, destination)
	}

	// The probe is sent on a socket of the destination's family, so its source is reported in the
	// same form: four bytes for IPv4, which a dual-stack UDP socket may have given as a mapped
	// IPv6 address.
	if destination.To4() != nil {
		if sourceIpv4 := sourceIp.To4(); sourceIpv4 != nil {
			sourceIp = sourceIpv4
		}
	}

	return sourceIp, nil
}

// allowBroadcast sets SO_BROADCAST on the route-lookup socket, so that a subnet's broadcast
// address, which a CIDR block contains, gets an answer rather than EACCES.
func allowBroadcast(_ string, _ string, rawConnection syscall.RawConn) error {
	var controlErr error
	err := rawConnection.Control(func(fd uintptr) {
		controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	})
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("raw conn control: %w", err))
	}
	if controlErr != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("setsockopt so broadcast: %w", controlErr))
	}

	return nil
}

// cachedSourceIpResolver remembers the resolver's answers per destination, up to a bound. The
// probes of one address are spread through the scan by the shuffle, so without a cache every port
// of an address would cost a route lookup.
type cachedSourceIpResolver struct {
	resolve SourceIpResolver
	mu      sync.Mutex
	entries map[[net.IPv6len]byte]net.IP
}

func newCachedSourceIpResolver(resolve SourceIpResolver) *cachedSourceIpResolver {
	return &cachedSourceIpResolver{resolve: resolve, entries: make(map[[net.IPv6len]byte]net.IP)}
}

func (resolver *cachedSourceIpResolver) Resolve(destination net.IP) (net.IP, error) {
	var key [net.IPv6len]byte
	copy(key[:], destination.To16())

	resolver.mu.Lock()
	sourceIp, ok := resolver.entries[key]
	resolver.mu.Unlock()
	if ok {
		return sourceIp, nil
	}

	sourceIp, err := resolver.resolve(destination)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	resolver.mu.Lock()
	if len(resolver.entries) < maxSourceIpCacheSize {
		resolver.entries[key] = sourceIp
	}
	resolver.mu.Unlock()

	return sourceIp, nil
}
