// Package port_scanner finds open TCP ports with SYN probes: a SYN is sent from a raw socket, the
// SYN/ACK that an open port answers with is captured with libpcap, and the kernel, which knows
// nothing of the connection, resets it. Sending needs CAP_NET_RAW.
package port_scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"

	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftNet "github.com/altshiftab/utils_go/pkg/net"
	"golang.org/x/sys/unix"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
	"github.com/altshiftab/port_scanner/pkg/port_scanner/port_scanner_config"
	"github.com/altshiftab/port_scanner/pkg/types/listener_handler"
)

// TransportTcp is the transport of every result; the scanner probes TCP only.
const TransportTcp = "tcp"

// Result is an open port: a host that answered a SYN with a SYN/ACK.
type Result struct {
	IpAddress string `json:"ip_address"`
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	IpVersion int    `json:"ip_version"`
}

// IsPrivileged reports whether the process may open raw sockets and capture packets: it is root,
// or it holds CAP_NET_RAW in its effective set.
func IsPrivileged() bool {
	if os.Geteuid() == 0 {
		return true
	}

	effective, err := effectiveCapabilities()
	if err != nil {
		return false
	}

	return effective&(1<<unix.CAP_NET_RAW) != 0
}

// effectiveCapabilities returns the low 32 bits of the calling thread's effective capability set,
// which is where CAP_NET_RAW lives. Capabilities are per thread, so the goroutine is pinned to its
// thread for the query.
func effectiveCapabilities() (uint32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	// Version 3 of the interface reports two 32-bit words per set; the kernel writes both, so
	// both must be there to write into.
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return 0, altshiftErrors.NewWithTrace(fmt.Errorf("unix capget: %w", err))
	}

	return data[0].Effective, nil
}

// ParseTargets turns targets, each an IP address or a CIDR block, into networks. Empty targets are
// skipped.
func ParseTargets(targets []string) ([]*net.IPNet, error) {
	networks := make([]*net.IPNet, 0, len(targets))
	for _, target := range targets {
		if target == "" {
			continue
		}

		network, err := altshiftNet.NetworkFromTarget(target)
		if err != nil {
			return nil, altshiftErrors.New(
				fmt.Errorf("%w: network from target: %w", altshiftErrors.ErrParseError, err),
				target,
			)
		}
		if network == nil {
			continue
		}

		networks = append(networks, network)
	}

	return networks, nil
}

// Scan probes the ports of every target, each an IP address or a CIDR block, and reports each open
// port to callback. It sets up and tears down what the scan needs: the source port and raw sockets,
// and a capture handle on every interface that is up (or the ones named in the options). The
// callback is invoked concurrently and must be safe for that.
func Scan(
	ctx context.Context,
	targets []string,
	ports []int,
	callback func(*Result),
	options ...port_scanner_config.Option,
) error {
	networks, err := ParseTargets(targets)
	if err != nil {
		return fmt.Errorf("parse targets: %w", err)
	}

	if err := ScanNetworks(ctx, networks, ports, callback, options...); err != nil {
		return fmt.Errorf("scan networks: %w", err)
	}

	return nil
}

// ScanNetworks is Scan for targets already parsed into networks.
func ScanNetworks(
	ctx context.Context,
	networks []*net.IPNet,
	ports []int,
	callback func(*Result),
	options ...port_scanner_config.Option,
) error {
	// Checked here rather than left to the scan loops: with a small target set
	// the concurrency limit is never reached, so a loop that only notices
	// cancellation while waiting for a slot would not notice it at all.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ctx err: %w", err)
	}

	if len(networks) == 0 {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("networks")),
		)
	}

	if len(ports) == 0 {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("ports")),
		)
	}

	if callback == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("callback"))
	}

	config := port_scanner_config.New(options...)
	if err := validateConfig(config); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	// A connect scan opens ordinary outbound sockets, so it is the one mode that
	// does not need the raw-socket privilege the check below insists on.
	if config.Mode == port_scanner_config.ModeConnect {
		if err := scanConnect(ctx, networks, ports, callback, config); err != nil {
			return fmt.Errorf("scan connect: %w", err)
		}

		return nil
	}

	if !IsPrivileged() {
		return altshiftErrors.NewWithTrace(portScannerErrors.ErrNotPrivileged)
	}

	listenHandler, err := listener_handler.New(ctx, config.SkipIpv6)
	if err != nil {
		return fmt.Errorf("listener handler new: %w", err)
	}
	defer func() {
		if err := listenHandler.Close(); err != nil {
			slog.WarnContext(
				altshiftContext.WithError(ctx, fmt.Errorf("listen handler close: %w", err)),
				"An error occurred when closing the listen handler.",
			)
		}
	}()

	pcapHandles, err := OpenPcapHandles(ctx, listenHandler.ListenPort, config.InterfaceNames)
	if err != nil {
		return altshiftErrors.New(fmt.Errorf("open pcap handles: %w", err), listenHandler.ListenPort)
	}
	defer ClosePcapHandles(pcapHandles)

	packetSources := make([]PacketSource, 0, len(pcapHandles))
	for _, pcapHandle := range pcapHandles {
		packetSources = append(packetSources, pcapHandle)
	}

	scanner, err := NewScanner(listenHandler, packetSources, callback, options...)
	if err != nil {
		return fmt.Errorf("new scanner: %w", err)
	}

	if err := scanner.Scan(ctx, networks, ports); err != nil {
		return fmt.Errorf("scanner scan: %w", err)
	}

	return nil
}
