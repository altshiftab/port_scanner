# port_scanner

A TCP SYN port scanner, as a library and a command-line tool. A SYN is sent to every port of every
target from a raw socket, the SYN/ACKs that open ports answer with are captured with libpcap, and
the kernel, which knows nothing of the connections, resets them.

Linux only. Needs `CAP_NET_RAW`, i.e. root or `setcap cap_net_raw+ep` on the binary. Building
needs the libpcap headers (cgo).

## Command line

```
port_scanner [-p PORTS] [-n INT] [-t DURATION] [-6] [-i NAME...] [-j] [-v] TARGET...
```

Targets are IP addresses or CIDR blocks. Open ports are printed one per line as `host:port` (or as
JSON objects with `-j`) as they are found; diagnostics go to stderr as JSON log lines.

```
sudo port_scanner -p 22,80,443,8000-8100 192.0.2.0/24 198.51.100.7
sudo port_scanner -6 -j 2001:db8::/120
```

`-p/--ports` takes a comma-separated list of ports and inclusive ranges and defaults to a built-in
list of the ~3500 most commonly open ports. `-n/--concurrency` (default 500) is how many probes may
be outstanding at once and `-t/--timeout` (default 1s) how long each waits for its reply, so a scan
sends at most `concurrency / timeout` probes per second. `-i/--interface` restricts capture to the
named interfaces; every interface that is up is captured on by default.

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
		// result.IpAddress, result.Port, result.Transport ("tcp"), result.IpVersion.
		// Each result arrives on a goroutine of its own, so this runs concurrently with
		// itself; Scan returns only after the last call has.
	},
	port_scanner_config.WithConcurrency(1000),
	port_scanner_config.WithTimeout(2*time.Second),
	port_scanner_config.WithSkipIpv6(true),
)
```

`Scan` sets up and tears down everything a scan needs. `ScanNetworks` takes parsed `*net.IPNet`
targets. For a scan that reuses sockets and capture handles, or reads packets from somewhere other
than libpcap, build a `Scanner` with `NewScanner` from a `listener_handler.ListenHandler` and
`PacketSource`s.

Input errors wrap `altshiftErrors.ErrValidationError` (bad ports, networks, options) or
`altshiftErrors.ErrParseError` (unparsable targets); running without `CAP_NET_RAW` returns
`portScannerErrors.ErrNotPrivileged`. A target the kernel has no route to, or whose probe cannot
be sent, is logged and skipped (once per network for routing failures); the scan fails with
`portScannerErrors.ErrNoProbesSent` only if not one probe went out. A capture handle that fails
mid-scan is logged and dropped; the scan fails only when none is left.

## How replies are matched

Each outstanding probe holds one of `Concurrency` slots. The slot number, plus a per-scan random
base, is the probe's sequence number, so the acknowledgement number of a SYN/ACK names the slot it
answers; the slot records which address and port were probed, and a reply is only accepted if it
comes from them. A slot is released by its reply or by its timeout, whichever comes first, and a
retransmitted SYN/ACK does not produce a second result.

## Development

```
GOEXPERIMENT=jsonv2 go build ./... && go vet ./... && go test -race ./...
custom-gcl run --config ~/.config/goland_go_linter/.golangci.yaml ./...
```

Everything but the tests that need `CAP_NET_RAW` runs unprivileged: the probe/reply loop is
exercised against fake sockets and capture sources. Run as root (`sudo -E "$(which go)" test ./...`)
to also run the end-to-end scan of the loopback interface (`TestScanEndToEnd`) and the raw-socket
and capture-handle setup; those tests skip themselves otherwise.
