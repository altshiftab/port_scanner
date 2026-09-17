package port_scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"

	"github.com/altshiftab/port_scanner/pkg/banner"
	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
	"github.com/altshiftab/port_scanner/pkg/port_scanner/port_scanner_config"
)

// maxConnectAddresses caps how many addresses one connect scan will enumerate.
// A connect scan walks its targets address by address, so a mistyped prefix is
// otherwise a run that never ends rather than an error.
const maxConnectAddresses = 1 << 20

// scanConnect finds open ports by completing a TCP handshake against each one.
//
// Unlike the SYN scan it has no capture side and no probe slots: each candidate
// is simply dialled. That is what lets it run unprivileged, and also what makes
// it slower - every filtered port costs a full connect timeout.
func scanConnect(
	ctx context.Context,
	networks []*net.IPNet,
	ports []int,
	callback func(*Result),
	config *port_scanner_config.Config,
) error {
	addresses, err := expandNetworks(networks, config.SkipIpv6)
	if err != nil {
		return fmt.Errorf("expand networks: %w", err)
	}

	if len(addresses) == 0 {
		return nil
	}

	semaphore := make(chan struct{}, config.Concurrency)
	var waitGroup sync.WaitGroup

	// probes counts what was launched and localFailures what never reached the network, so that a
	// scan which could not dial at all can say so rather than reporting nothing open.
	probes := int64(len(addresses)) * int64(len(ports))
	var localFailures atomic.Int64

	for _, address := range addresses {
		for _, port := range ports {
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				waitGroup.Wait()
				return fmt.Errorf("ctx err: %w", ctx.Err())
			}

			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() { <-semaphore }()

				connection, err := connectOpen(ctx, address, port, config.ConnectTimeout)
				if err != nil {
					if isLocalFailure(err) {
						localFailures.Add(1)
					}

					return
				}

				result := &Result{
					IpAddress: address.String(),
					Port:      port,
					Transport: TransportTcp,
					IpVersion: ipVersionOf(address),
				}

				// The connection the scan proved the port with is the one the banner is read from,
				// so asking costs no second handshake -- which is the whole reason a connect scan
				// is the cheap place to ask.
				if config.Banner {
					result.Banner = banner.Grab(ctx, connection, port, config.BannerOptions...)
				}

				_ = connection.Close()

				callback(result)
			}()
		}
	}

	waitGroup.Wait()

	// A dial that fails because the context ended is indistinguishable from a dial that failed
	// because the port is shut, so a scan cut short reports every remaining port closed. Left
	// unreported that is the one wrong answer nothing downstream can catch: a clean scan that
	// found nothing. The context is therefore checked after the wait as well as in the loop, which
	// only notices while waiting for a slot.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ctx err: %w", err)
	}

	// Every dial failing locally -- no file descriptors, no route, no permission -- is the same
	// kind of lie: nothing was ever asked, and a scan that asked nothing has not found that
	// nothing is open. SYN mode says so with ErrNoProbesSent and this says it the same way.
	if probes > 0 && localFailures.Load() == probes {
		return altshiftErrors.NewWithTrace(portScannerErrors.ErrNoProbesSent, probes)
	}

	return nil
}

// isLocalFailure reports whether a dial failed before it ever reached the network: the file
// descriptors ran out, there is no route, or the sandbox refused.
//
// It is the distinction between "the target did not answer" and "we never asked", which a connect
// scan otherwise loses -- both arrive as a failed dial, and both would be read as a shut port.
func isLocalFailure(err error) bool {
	if err == nil {
		return false
	}

	// A dial the context ended is not a local failure in this sense; it is reported separately and
	// would otherwise mask the check.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	syscallError, ok := errors.AsType[syscall.Errno](err)
	if !ok {
		return false
	}

	switch syscallError {
	case syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.EPERM, syscall.EACCES, syscall.EAFNOSUPPORT,
		syscall.ENETUNREACH, syscall.EADDRNOTAVAIL, syscall.EINVAL:
		return true
	default:
		return false
	}
}

// connectOpen returns the connection a completed handshake to the address left open.
//
// The error is returned rather than folded into "not open" because the ways a dial fails are not
// all the same thing. Refused, filtered and timed out are answers about the port; out of file
// descriptors or no route are answers about us, and the caller counts those separately.
//
// The connection is handed back rather than closed here because it is worth something: it is a
// connection to the service, which is what a banner is read from. The caller closes it.
func connectOpen(
	ctx context.Context,
	address net.IP,
	port int,
	timeout time.Duration,
) (net.Conn, error) {
	dialContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var dialer net.Dialer
	connection, err := dialer.DialContext(
		dialContext,
		"tcp",
		net.JoinHostPort(address.String(), strconv.Itoa(port)),
	)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("dialer dial context: %w", err),
			address.String(), port,
		)
	}

	return connection, nil
}

func ipVersionOf(address net.IP) int {
	if address.To4() != nil {
		return ipv4Version
	}
	return ipv6Version
}

// expandNetworks enumerates every scannable address the networks cover.
//
// For an IPv4 network larger than a /31 the network and broadcast addresses are
// left out: neither answers a scan, and dialling them only wastes a timeout.
func expandNetworks(networks []*net.IPNet, skipIpv6 bool) ([]net.IP, error) {
	var addresses []net.IP

	for _, network := range networks {
		if network == nil {
			continue
		}

		// An address and its mask have to be the same width before anything can be done with them.
		// net.ParseCIDR returns a four-byte IP for an IPv4 network, but net.ParseIP returns a
		// sixteen-byte one, and pairing that with net.CIDRMask(32, 32) is what anyone assembling an
		// IPNet by hand produces. Masking a sixteen-byte address with a four-byte mask yields four
		// bytes, which then matches nothing -- so the scan silently enumerated no addresses at all.
		address, mask := normaliseNetwork(network)
		if address == nil || len(address) != len(mask) {
			continue
		}

		if skipIpv6 && address.To4() == nil {
			continue
		}

		ones, bits := mask.Size()
		if bits == 0 {
			continue
		}

		// A /31 or /32 has no network or broadcast address to leave out; every
		// address in it is a host.
		skipEdges := bits == 32 && ones < 31

		current := make(net.IP, len(address))
		copy(current, address.Mask(mask))

		normalised := &net.IPNet{IP: address, Mask: mask}

		for normalised.Contains(current) {
			if !skipEdges || !isNetworkOrBroadcast(current, normalised) {
				if len(addresses) >= maxConnectAddresses {
					return nil, altshiftErrors.NewWithTrace(
						fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, portScannerErrors.ErrTooManyAddresses),
						maxConnectAddresses,
					)
				}

				address := make(net.IP, len(current))
				copy(address, current)
				addresses = append(addresses, address)
			}

			if !incrementAddress(current) {
				break
			}
		}
	}

	return addresses, nil
}

// normaliseNetwork returns the network's address and mask at a single width.
//
// An IPv4 address is reduced to its four-byte form, and a sixteen-byte mask over one to its last
// four bytes -- but only when the leading twelve bytes are the all-ones of the IPv4-mapped prefix.
// A mask that covers less than that is not describing an IPv4 network at all, so it and its address
// are left at sixteen bytes and treated as the IPv6 network they are.
func normaliseNetwork(network *net.IPNet) (net.IP, net.IPMask) {
	address := network.IP
	mask := network.Mask

	if address4 := address.To4(); address4 != nil {
		switch len(mask) {
		case net.IPv4len:
			return address4, mask
		case net.IPv6len:
			if isIpv4MappedMask(mask) {
				return address4, mask[12:]
			}
		}
	}

	if address16 := address.To16(); address16 != nil && len(mask) == net.IPv6len {
		return address16, mask
	}

	return address, mask
}

// isIpv4MappedMask reports whether a sixteen-byte mask keeps the whole of the IPv4-mapped prefix,
// which is what makes its last four bytes an IPv4 mask.
func isIpv4MappedMask(mask net.IPMask) bool {
	for _, octet := range mask[:12] {
		if octet != 0xff {
			return false
		}
	}

	return true
}

func isNetworkOrBroadcast(address net.IP, network *net.IPNet) bool {
	if address.Equal(network.IP.Mask(network.Mask)) {
		return true
	}

	broadcast := make(net.IP, len(network.IP))
	copy(broadcast, network.IP.Mask(network.Mask))
	for i := range broadcast {
		broadcast[i] |= ^network.Mask[i]
	}

	return address.Equal(broadcast)
}

// incrementAddress advances the address in place, reporting false when it wraps
// past the end of the address space.
func incrementAddress(address net.IP) bool {
	for i := len(address) - 1; i >= 0; i-- {
		address[i]++
		if address[i] != 0 {
			return true
		}
	}

	return false
}
