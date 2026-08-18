package port_scanner

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
	"github.com/altshiftab/port_scanner/pkg/port_scanner/port_scanner_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
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

				if !connectOpen(ctx, address, port, config.ConnectTimeout) {
					return
				}

				callback(&Result{
					IpAddress: address.String(),
					Port:      port,
					Transport: "tcp",
					IpVersion: ipVersionOf(address),
				})
			}()
		}
	}

	waitGroup.Wait()

	return nil
}

// connectOpen reports whether a handshake to the address completes. Every way it
// can fail - refused, filtered, unreachable, timed out - means the same thing to
// a scan: not open.
func connectOpen(ctx context.Context, address net.IP, port int, timeout time.Duration) bool {
	dialContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var dialer net.Dialer
	connection, err := dialer.DialContext(
		dialContext,
		"tcp",
		net.JoinHostPort(address.String(), strconv.Itoa(port)),
	)
	if err != nil {
		return false
	}

	_ = connection.Close()

	return true
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

		if skipIpv6 && network.IP.To4() == nil {
			continue
		}

		ones, bits := network.Mask.Size()
		if bits == 0 {
			continue
		}

		// A /31 or /32 has no network or broadcast address to leave out; every
		// address in it is a host.
		skipEdges := bits == 32 && ones < 31

		current := make(net.IP, len(network.IP))
		copy(current, network.IP.Mask(network.Mask))

		for network.Contains(current) {
			if !skipEdges || !isNetworkOrBroadcast(current, network) {
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
