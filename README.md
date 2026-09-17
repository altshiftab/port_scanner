# port_scanner

A TCP port scanner, as a library and a command-line tool, in two modes.

**SYN.** A SYN is sent to every port of every target from a raw socket, the SYN/ACKs that open ports
answer with are captured from an `AF_PACKET` socket, and the kernel, which knows nothing of the
connections, resets them. Fast, and it leaves the target with no connection to log. Linux only, and
it needs `CAP_NET_RAW`: root, or `setcap cap_net_raw+ep` on the binary.

**Connect.** An ordinary TCP handshake is completed against every candidate instead. It needs no
privileges at all, which is what makes it the mode for a container or a sandbox — Google Cloud Run
grants no `CAP_NET_RAW` and no `AF_PACKET`, so SYN mode cannot run there under any configuration.
The costs are that it is slower, every filtered port costing a full connect timeout, and that the
target sees and logs each connection.

Pure Go, no cgo and no libpcap: capture is an `AF_PACKET` socket opened through `gopacket/pcapgo`,
so `CGO_ENABLED=0` builds a static binary that drops into a `FROM scratch` image.

## Command line

```
port_scanner [-p PORTS] [-n INT] [-t DURATION] [-6] [-c] [--connect-timeout DURATION]
             [-b] [-i NAME...] [-j] [-v] TARGET...
```

Targets are IP addresses or CIDR blocks — not host names. Open ports are printed one per line as
`host:port` (or as JSON objects with `-j`) as they are found; diagnostics go to stderr as JSON log
lines.

```
sudo port_scanner -p 22,80,443,8000-8100 192.0.2.0/24 198.51.100.7
sudo port_scanner -6 -j 2001:db8::/120
port_scanner --connect --banner -p 22,80,443 192.0.2.7
```

`-p/--ports` takes a comma-separated list of ports and inclusive ranges and defaults to a built-in
list of the ~3500 most commonly open ports. `-n/--concurrency` (default 500) is how many probes may
be outstanding at once and `-t/--timeout` (default 1s) how long each waits for its reply.
`-i/--interface` restricts capture to the named interfaces; every interface that is up is captured
on by default.

`-c/--connect` selects connect mode, whose per-handshake bound is `--connect-timeout` (default 2s)
rather than `-t`. `-b/--banner` asks each open port what is behind it and appends the service and
what it said to the line.

## Library

```go
import (
	"github.com/altshiftab/port_scanner/pkg/port_scanner"
	"github.com/altshiftab/port_scanner/pkg/port_scanner/port_scanner_config"
)

err := port_scanner.Scan(
	ctx,
	[]string{"192.0.2.0/24", "198.51.100.7"},
	[]int{22, 80, 443},
	func(result *port_scanner.Result) {
		// result.IpAddress, result.Port, result.Transport ("tcp"), result.IpVersion,
		// and result.Banner where banners were asked for.
		// Each result arrives on a goroutine of its own, so this runs concurrently with
		// itself; Scan returns only after the last call has.
	},
	port_scanner_config.WithMode(port_scanner_config.ModeConnect),
	port_scanner_config.WithConcurrency(1000),
	port_scanner_config.WithConnectTimeout(2*time.Second),
	port_scanner_config.WithSkipIpv6(true),
)
```

`Scan` sets up and tears down whatever the mode needs. `ScanNetworks` takes parsed `*net.IPNet`
targets. For a SYN scan that reuses sockets and capture handles, or reads packets from somewhere
other than an `AF_PACKET` socket, build a `Scanner` with `NewScanner` from a
`listener_handler.ListenHandler` and `PacketSource`s.

### Banners

`port_scanner_config.WithBanner(true)` asks each open port what is behind it, and fills
`Result.Banner` with what it said, the service that names, and the TLS handshake where there was
one. Tunables are `banner_config` options passed through `WithBannerOptions`.

Only open ports are asked, and open ports are rare, so what this costs a scan is a function of what
it finds rather than of what it probes. A connect scan reads the banner from the connection it
already has; a SYN scan has none, so it opens one — which the target sees.

The `banner` package is usable on its own, against a connection or an address:

```go
grabbed := banner.GrabAddress(ctx, "192.0.2.7", 443, banner_config.WithTimeout(2*time.Second))
```

It tries the cheapest thing first: a read, since most services worth naming greet whoever connects;
then an HTTP request, for the ones that stay silent until spoken to; then a TLS handshake, which is
tried *first* on the ports that conventionally speak TLS and last on the ports that do not.

`Banner.Text` is a single line of printable ASCII, and nothing else — a banner is arbitrary bytes
from a stranger that end up in a database column and a report. A banner that is not text at all is
mined only for the stretches long enough to be something rather than coincidence, so a binary
handshake does not come out as a line of mojibake. `Banner.Raw` keeps what was actually on the wire.

### Errors

Input errors wrap `altshiftErrors.ErrValidationError` (bad ports, networks, options) or
`altshiftErrors.ErrParseError` (unparsable targets); running SYN mode without `CAP_NET_RAW` returns
`portScannerErrors.ErrNotPrivileged`.

A scan whose context ends returns that context's error rather than the results it had got to. That
matters more than it sounds: a dial that fails because the deadline passed is indistinguishable from
one that failed because the port is shut, so a scan that swallowed the cancellation would report a
clean run that found nothing.

A target the kernel has no route to, or whose probe cannot be sent, is logged and skipped (once per
network for routing failures). A scan fails with `portScannerErrors.ErrNoProbesSent` if not one
probe went out — in connect mode, if every dial failed locally (no file descriptors, no route, no
permission) rather than being answered.

A capture handle that fails mid-scan is logged and dropped; the scan fails only when none is left.

## How SYN replies are matched

Each outstanding probe holds one of `Concurrency` slots. The slot number, plus a per-scan random
base, is the probe's sequence number, so the acknowledgement number of a SYN/ACK names the slot it
answers; the slot records which address and port were probed, and a reply is only accepted if it
comes from them. A slot is released by its reply or by its timeout, whichever comes first, and a
retransmitted SYN/ACK does not produce a second result.

Overlapping targets are not deduplicated, so an address covered by two of them is probed — and
reported — once for each.

## Shutdown

An `AF_PACKET` read has no timeout: it returns when a frame arrives or when the handle is closed.
Cancelling a scan therefore cannot wake a reader waiting on a quiet interface, and since a `Scanner`
does not own its packet sources it cannot close them itself. So `Scan` gives its readers a moment
and then returns, leaving any still parked to be freed by the caller closing the sources — which
`ScanNetworks` does immediately. A reader that outlives its scan delivers no further results.

The consequence for a caller building its own `Scanner`: close the packet sources once `Scan`
returns, or those goroutines stay parked.

## Development

```
go build ./... && go vet ./... && go test -race ./...
custom-gcl run --config ~/.config/goland_go_linter/.golangci.yaml ./...
```

Everything but the tests that need `CAP_NET_RAW` runs unprivileged: the probe/reply loop is
exercised against fake sockets and capture sources, and the banner grabs against real loopback
listeners. Run as root (`sudo -E "$(which go)" test ./...`) to also run the end-to-end scan of the
loopback interface (`TestScanEndToEnd`) and the raw-socket and capture-handle setup; those tests
skip themselves otherwise.
