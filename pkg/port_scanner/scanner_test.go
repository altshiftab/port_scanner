package port_scanner

import (
	"context"
	"errors"
	"math"
	"net"
	"slices"
	"sort"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
	"github.com/altshiftab/port_scanner/pkg/port_scanner/port_scanner_config"
	"github.com/altshiftab/port_scanner/pkg/types/listener_handler"
)

const (
	testListenPort = 40000
	testSourceIp   = "192.0.2.100"
	// testTimeout is the probe timeout used by scans in tests; short, so that scans of a few
	// unanswered probes finish quickly.
	testTimeout = 50 * time.Millisecond
)

var (
	errNoBufferSpace      = errors.New("no buffer space available")
	errCaptureBroke       = errors.New("capture handle broke")
	errNetworkUnreachable = errors.New("network is unreachable")
)

// synAckFor builds the SYN/ACK a target would send in answer to a probe.
func synAckFor(t *testing.T, probe *sentProbe, linkType layers.LinkType) []byte {
	t.Helper()

	destinationIp := testSourceIp
	if probe.destination.To4() == nil {
		destinationIp = "2001:db8::ffff"
	}

	return buildPacket(t, &packetSpec{
		linkType:      linkType,
		sourceIp:      probe.destination.String(),
		destinationIp: destinationIp,
		sourcePort:    uint16(probe.tcp.DstPort),
		destPort:      uint16(probe.tcp.SrcPort),
		seq:           777,
		ack:           probe.tcp.Seq + 1,
		syn:           true,
		ackFlag:       true,
	})
}

// testScanner wires a Scanner to fake sockets and a fake capture source.
type testScanner struct {
	scanner   *Scanner
	source    *fakePacketSource
	ipv4Conn  *fakePacketConn
	ipv6Conn  *fakePacketConn
	collector *resultCollector
}

func newTestScanner(t *testing.T, options ...port_scanner_config.Option) *testScanner {
	t.Helper()

	source := newFakePacketSource(layers.LinkTypeEthernet)
	t.Cleanup(source.close)

	ipv4Conn := &fakePacketConn{}
	ipv6Conn := &fakePacketConn{}
	listenHandler := &listener_handler.ListenHandler{
		ListenPort:        testListenPort,
		TcpIpv4Connection: ipv4Conn,
		TcpIpv6Connection: ipv6Conn,
	}

	collector := &resultCollector{}

	options = append(
		[]port_scanner_config.Option{
			port_scanner_config.WithTimeout(testTimeout),
			port_scanner_config.WithSendRetryWait(time.Millisecond),
		},
		options...,
	)

	scanner, err := NewScanner(listenHandler, []PacketSource{source}, collector.callback, options...)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	scanner.resolveSourceIp = fixedSourceIp(testSourceIp)

	return &testScanner{
		scanner:   scanner,
		source:    source,
		ipv4Conn:  ipv4Conn,
		ipv6Conn:  ipv6Conn,
		collector: collector,
	}
}

func resultKeys(results []*Result) []string {
	keys := make([]string, 0, len(results))
	for _, result := range results {
		keys = append(keys, net.JoinHostPort(result.IpAddress, strconv.Itoa(result.Port)))
	}
	sort.Strings(keys)

	return keys
}

func TestScanReportsOpenPorts(t *testing.T) {
	t.Parallel()

	open := map[string]bool{"192.0.2.1:80": true, "192.0.2.2:443": true, "[2001:db8::1]:22": true}

	testScanner := newTestScanner(t)
	answer := func(probe *sentProbe) {
		key := net.JoinHostPort(probe.destination.String(), strconv.Itoa(int(probe.tcp.DstPort)))
		if open[key] {
			testScanner.source.inject(synAckFor(t, probe, layers.LinkTypeEthernet))
		}
	}
	testScanner.ipv4Conn.onSend = answer
	testScanner.ipv6Conn.onSend = answer

	networks := []*net.IPNet{mustParseCidr(t, "192.0.2.0/30"), mustParseCidr(t, "2001:db8::/127")}
	ports := []int{80, 443, 22}

	err := testScanner.scanner.Scan(context.Background(), networks, ports)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if got, want := resultKeys(testScanner.collector.all()), []string{"192.0.2.1:80", "192.0.2.2:443", "[2001:db8::1]:22"}; !slices.Equal(got, want) {
		t.Fatalf("results = %v, want %v", got, want)
	}

	// Every target was probed exactly once, with the listen port as source and a SYN.
	sent := append(testScanner.ipv4Conn.sentProbes(), testScanner.ipv6Conn.sentProbes()...)
	if got, want := len(sent), (4+2)*len(ports); got != want {
		t.Fatalf("%d probes sent, want %d", got, want)
	}
	seen := make(map[string]int)
	for _, probe := range sent {
		if probe.tcp.SrcPort != testListenPort {
			t.Errorf("probe source port = %d, want %d", probe.tcp.SrcPort, testListenPort)
		}
		if !probe.tcp.SYN || probe.tcp.ACK {
			t.Errorf("probe flags SYN=%v ACK=%v, want a bare SYN", probe.tcp.SYN, probe.tcp.ACK)
		}
		seen[net.JoinHostPort(probe.destination.String(), strconv.Itoa(int(probe.tcp.DstPort)))]++
	}
	for key, count := range seen {
		if count != 1 {
			t.Errorf("target %s probed %d times", key, count)
		}
	}

	for _, result := range testScanner.collector.all() {
		if result.Transport != TransportTcp {
			t.Errorf("Transport = %q, want %q", result.Transport, TransportTcp)
		}
		wantVersion := 4
		if net.ParseIP(result.IpAddress).To4() == nil {
			wantVersion = 6
		}
		if result.IpVersion != wantVersion {
			t.Errorf("IpVersion = %d for %s, want %d", result.IpVersion, result.IpAddress, wantVersion)
		}
	}
}

func TestScanSequenceNumbersEncodeSlots(t *testing.T) {
	t.Parallel()

	const concurrency = 4

	testScanner := newTestScanner(t, port_scanner_config.WithConcurrency(concurrency))

	err := testScanner.scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.0/29")}, []int{80})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	base := testScanner.scanner.sequenceBase
	for _, probe := range testScanner.ipv4Conn.sentProbes() {
		if slot := probe.tcp.Seq - base; slot >= concurrency {
			t.Errorf("probe sequence number %d names slot %d, outside [0, %d)", probe.tcp.Seq, slot, concurrency)
		}
	}
}

func TestScanIgnoresRepliesThatMatchNoProbe(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		mangle func(probe *sentProbe) *packetSpec
	}{
		{
			name: "retransmitted syn/ack is reported once",
			mangle: func(probe *sentProbe) *packetSpec {
				return &packetSpec{
					linkType: layers.LinkTypeEthernet, sourceIp: probe.destination.String(), destinationIp: testSourceIp,
					sourcePort: uint16(probe.tcp.DstPort), destPort: uint16(probe.tcp.SrcPort),
					ack: probe.tcp.Seq + 1, syn: true, ackFlag: true,
				}
			},
		},
		{
			name: "wrong source port",
			mangle: func(probe *sentProbe) *packetSpec {
				return &packetSpec{
					linkType: layers.LinkTypeEthernet, sourceIp: probe.destination.String(), destinationIp: testSourceIp,
					sourcePort: uint16(probe.tcp.DstPort) + 1, destPort: uint16(probe.tcp.SrcPort),
					ack: probe.tcp.Seq + 1, syn: true, ackFlag: true,
				}
			},
		},
		{
			name: "wrong source address",
			mangle: func(probe *sentProbe) *packetSpec {
				return &packetSpec{
					linkType: layers.LinkTypeEthernet, sourceIp: "198.51.100.1", destinationIp: testSourceIp,
					sourcePort: uint16(probe.tcp.DstPort), destPort: uint16(probe.tcp.SrcPort),
					ack: probe.tcp.Seq + 1, syn: true, ackFlag: true,
				}
			},
		},
		{
			name: "acknowledgement names no slot",
			mangle: func(probe *sentProbe) *packetSpec {
				return &packetSpec{
					linkType: layers.LinkTypeEthernet, sourceIp: probe.destination.String(), destinationIp: testSourceIp,
					sourcePort: uint16(probe.tcp.DstPort), destPort: uint16(probe.tcp.SrcPort),
					ack: probe.tcp.Seq + 1000, syn: true, ackFlag: true,
				}
			},
		},
		{
			name: "acknowledgement of the sequence number itself",
			mangle: func(probe *sentProbe) *packetSpec {
				return &packetSpec{
					linkType: layers.LinkTypeEthernet, sourceIp: probe.destination.String(), destinationIp: testSourceIp,
					sourcePort: uint16(probe.tcp.DstPort), destPort: uint16(probe.tcp.SrcPort),
					ack: probe.tcp.Seq, syn: true, ackFlag: true,
				}
			},
		},
		{
			name: "rst/ack",
			mangle: func(probe *sentProbe) *packetSpec {
				return &packetSpec{
					linkType: layers.LinkTypeEthernet, sourceIp: probe.destination.String(), destinationIp: testSourceIp,
					sourcePort: uint16(probe.tcp.DstPort), destPort: uint16(probe.tcp.SrcPort),
					ack: probe.tcp.Seq + 1, rst: true, ackFlag: true,
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testScanner := newTestScanner(t, port_scanner_config.WithConcurrency(2))
			testScanner.ipv4Conn.onSend = func(probe *sentProbe) {
				// The genuine reply first, then the mangled one, twice, so that a duplicate as
				// well as each kind of mismatch is exercised against a slot that is still held.
				testScanner.source.inject(synAckFor(t, probe, layers.LinkTypeEthernet))
				testScanner.source.inject(buildPacket(t, testCase.mangle(probe)))
				testScanner.source.inject(buildPacket(t, testCase.mangle(probe)))
			}

			err := testScanner.scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.1/32")}, []int{80})
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}

			if got, want := resultKeys(testScanner.collector.all()), []string{"192.0.2.1:80"}; !slices.Equal(got, want) {
				t.Fatalf("results = %v, want %v", got, want)
			}
		})
	}
}

func TestScanFreesSlotsOnTimeout(t *testing.T) {
	t.Parallel()

	// One slot and eight unanswered targets: the scan can only proceed if the timeout frees the
	// slot each time, and must take at least eight timeouts.
	testScanner := newTestScanner(t, port_scanner_config.WithConcurrency(1))

	start := time.Now()
	err := testScanner.scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.0/29")}, []int{80})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	elapsed := time.Since(start)

	if got, want := len(testScanner.ipv4Conn.sentProbes()), 8; got != want {
		t.Fatalf("%d probes sent, want %d", got, want)
	}
	if elapsed < 8*testTimeout {
		t.Fatalf("scan took %s, less than eight timeouts of %s", elapsed, testTimeout)
	}
	if len(testScanner.collector.all()) != 0 {
		t.Fatalf("results = %v, want none", testScanner.collector.all())
	}
}

func TestScanFreesSlotsOnReply(t *testing.T) {
	t.Parallel()

	// One slot and many answered targets: replies free the slot, so the scan finishes in far
	// less than a timeout per target.
	testScanner := newTestScanner(t, port_scanner_config.WithConcurrency(1), port_scanner_config.WithTimeout(time.Second))
	testScanner.ipv4Conn.onSend = func(probe *sentProbe) {
		testScanner.source.inject(synAckFor(t, probe, layers.LinkTypeEthernet))
	}

	start := time.Now()
	err := testScanner.scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.0/28")}, []int{80})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	elapsed := time.Since(start)

	if got, want := len(testScanner.collector.all()), 16; got != want {
		t.Fatalf("%d results, want %d", got, want)
	}
	// The scan lingers one timeout after the last probe; sixteen serial timeouts would be far
	// longer.
	if elapsed > 3*time.Second {
		t.Fatalf("scan took %s; slots were not freed by replies", elapsed)
	}
}

func TestScanStopsWhenContextEnds(t *testing.T) {
	t.Parallel()

	testScanner := newTestScanner(t, port_scanner_config.WithConcurrency(1), port_scanner_config.WithTimeout(time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := testScanner.scanner.Scan(ctx, []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")}, []int{80})
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Scan() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Scan() took %s after the context ended", elapsed)
	}
	if sent := len(testScanner.ipv4Conn.sentProbes()); sent >= 256 {
		t.Fatalf("%d probes sent, want the scan cut short", sent)
	}
}

func TestScanRejectsAlreadyEndedContext(t *testing.T) {
	t.Parallel()

	testScanner := newTestScanner(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := testScanner.scanner.Scan(ctx, []*net.IPNet{mustParseCidr(t, "192.0.2.1/32")}, []int{80})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan() error = %v, want %v", err, context.Canceled)
	}
	if sent := len(testScanner.ipv4Conn.sentProbes()); sent != 0 {
		t.Fatalf("%d probes sent, want none", sent)
	}
}

func TestScanSendFailures(t *testing.T) {
	t.Parallel()

	const attempts = 3

	testCases := []struct {
		name         string
		writeErr     error
		wantAttempts int
	}{
		{name: "transient error is retried", writeErr: syscall.ENOBUFS, wantAttempts: attempts},
		{name: "interrupted call is retried", writeErr: syscall.EINTR, wantAttempts: attempts},
		{name: "permanent error is not retried", writeErr: syscall.EPERM, wantAttempts: 1},
		{name: "unknown error is not retried", writeErr: errNoBufferSpace, wantAttempts: 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testScanner := newTestScanner(t, port_scanner_config.WithSendAttempts(attempts))
			testScanner.ipv4Conn.writeErr = testCase.writeErr

			// Two targets: every probe fails to send, so the scan fails for want of a single probe.
			err := testScanner.scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.0/31")}, []int{80})
			if !errors.Is(err, portScannerErrors.ErrNoProbesSent) {
				t.Fatalf("Scan() error = %v, want %v", err, portScannerErrors.ErrNoProbesSent)
			}
			if !errors.Is(err, testCase.writeErr) {
				t.Fatalf("Scan() error = %v, want it to wrap %v", err, testCase.writeErr)
			}

			if got, want := testScanner.ipv4Conn.attempts(), 2*testCase.wantAttempts; got != want {
				t.Fatalf("%d send attempts, want %d", got, want)
			}
			if len(testScanner.collector.all()) != 0 {
				t.Fatalf("results = %v, want none", testScanner.collector.all())
			}
		})
	}
}

func TestScanSkipsTargetsWhoseProbeCannotBeSent(t *testing.T) {
	t.Parallel()

	// IPv4 sends fail, IPv6 sends succeed and are answered: the scan must complete with the IPv6
	// results and no error.
	testScanner := newTestScanner(t)
	testScanner.ipv4Conn.writeErr = syscall.EPERM
	testScanner.ipv6Conn.onSend = func(probe *sentProbe) {
		testScanner.source.inject(synAckFor(t, probe, layers.LinkTypeEthernet))
	}

	networks := []*net.IPNet{mustParseCidr(t, "192.0.2.0/30"), mustParseCidr(t, "2001:db8::1/128")}
	err := testScanner.scanner.Scan(context.Background(), networks, []int{80})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if got, want := resultKeys(testScanner.collector.all()), []string{"[2001:db8::1]:80"}; !slices.Equal(got, want) {
		t.Fatalf("results = %v, want %v", got, want)
	}
}

func TestScanFailsOnReaderError(t *testing.T) {
	t.Parallel()

	readErr := errCaptureBroke
	source := &erroringPacketSource{err: readErr}

	listenHandler := &listener_handler.ListenHandler{
		ListenPort:        testListenPort,
		TcpIpv4Connection: &fakePacketConn{},
	}
	scanner, err := NewScanner(listenHandler, []PacketSource{source}, func(*Result) {}, port_scanner_config.WithTimeout(time.Second))
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	scanner.resolveSourceIp = fixedSourceIp(testSourceIp)

	start := time.Now()
	err = scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")}, []int{80})
	if !errors.Is(err, readErr) {
		t.Fatalf("Scan() error = %v, want %v", err, readErr)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Scan() took %s after the reader failed", elapsed)
	}
}

// erroringPacketSource fails its first read.
type erroringPacketSource struct {
	err error
}

func (source *erroringPacketSource) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (source *erroringPacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, source.err
}

func TestScanContinuesWhenOnePacketSourceFails(t *testing.T) {
	t.Parallel()

	good := newFakePacketSource(layers.LinkTypeEthernet)
	t.Cleanup(good.close)
	bad := &erroringPacketSource{err: errCaptureBroke}

	ipv4Conn := &fakePacketConn{}
	listenHandler := &listener_handler.ListenHandler{ListenPort: testListenPort, TcpIpv4Connection: ipv4Conn}
	collector := &resultCollector{}

	scanner, err := NewScanner(
		listenHandler,
		[]PacketSource{bad, good},
		collector.callback,
		port_scanner_config.WithTimeout(testTimeout),
	)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	scanner.resolveSourceIp = fixedSourceIp(testSourceIp)
	ipv4Conn.onSend = func(probe *sentProbe) {
		good.inject(synAckFor(t, probe, layers.LinkTypeEthernet))
	}

	if err := scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.0/30")}, []int{80}); err != nil {
		t.Fatalf("Scan() error = %v; one failed source out of two should not fail the scan", err)
	}

	if got, want := len(collector.all()), 4; got != want {
		t.Fatalf("%d results, want %d", got, want)
	}
}

func TestScanDeduplicatesAcrossPacketSources(t *testing.T) {
	t.Parallel()

	// The same reply seen on two interfaces is one result.
	first := newFakePacketSource(layers.LinkTypeEthernet)
	t.Cleanup(first.close)
	second := newFakePacketSource(layers.LinkTypeEthernet)
	t.Cleanup(second.close)

	ipv4Conn := &fakePacketConn{}
	listenHandler := &listener_handler.ListenHandler{ListenPort: testListenPort, TcpIpv4Connection: ipv4Conn}
	collector := &resultCollector{}

	scanner, err := NewScanner(
		listenHandler,
		[]PacketSource{first, second},
		collector.callback,
		port_scanner_config.WithTimeout(testTimeout),
	)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	scanner.resolveSourceIp = fixedSourceIp(testSourceIp)
	ipv4Conn.onSend = func(probe *sentProbe) {
		reply := synAckFor(t, probe, layers.LinkTypeEthernet)
		first.inject(reply)
		second.inject(reply)
	}

	if err := scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.0/29")}, []int{80}); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if got, want := len(collector.all()), 8; got != want {
		t.Fatalf("%d results, want %d (one per target, not per source)", got, want)
	}
}

func TestScanTreatsExhaustedPacketSourceAsSilent(t *testing.T) {
	t.Parallel()

	testScanner := newTestScanner(t)
	testScanner.source.close()

	start := time.Now()
	err := testScanner.scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.1/32")}, []int{80})
	if err != nil {
		t.Fatalf("Scan() error = %v; a source at EOF is not a failure", err)
	}
	if elapsed := time.Since(start); elapsed < testTimeout {
		t.Fatalf("Scan() took %s, less than one timeout; the probe was not waited for", elapsed)
	}
	if len(testScanner.collector.all()) != 0 {
		t.Fatalf("results = %v, want none", testScanner.collector.all())
	}
}

func TestScanFailsWhenNoSourceIpCanBeResolved(t *testing.T) {
	t.Parallel()

	resolveErr := errNetworkUnreachable

	testScanner := newTestScanner(t)
	testScanner.scanner.resolveSourceIp = func(net.IP) (net.IP, error) { return nil, resolveErr }

	err := testScanner.scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.0/30")}, []int{80})
	if !errors.Is(err, portScannerErrors.ErrNoProbesSent) {
		t.Fatalf("Scan() error = %v, want %v", err, portScannerErrors.ErrNoProbesSent)
	}
	if !errors.Is(err, resolveErr) {
		t.Fatalf("Scan() error = %v, want it to wrap %v", err, resolveErr)
	}
	if sent := len(testScanner.ipv4Conn.sentProbes()); sent != 0 {
		t.Fatalf("%d probes sent, want none", sent)
	}
}

func TestScanSkipsUnroutableTargets(t *testing.T) {
	t.Parallel()

	// One network is unroutable, the other is answered: the scan completes with the latter's
	// results and no error, and probes only the routable targets.
	testScanner := newTestScanner(t)
	unroutable := mustParseCidr(t, "198.51.100.0/30")
	testScanner.scanner.resolveSourceIp = func(destination net.IP) (net.IP, error) {
		if unroutable.Contains(destination) {
			return nil, errNetworkUnreachable
		}
		return net.ParseIP(testSourceIp).To4(), nil
	}
	testScanner.ipv4Conn.onSend = func(probe *sentProbe) {
		testScanner.source.inject(synAckFor(t, probe, layers.LinkTypeEthernet))
	}

	networks := []*net.IPNet{unroutable, mustParseCidr(t, "192.0.2.0/30")}
	err := testScanner.scanner.Scan(context.Background(), networks, []int{80})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	want := []string{"192.0.2.0:80", "192.0.2.1:80", "192.0.2.2:80", "192.0.2.3:80"}
	if got := resultKeys(testScanner.collector.all()); !slices.Equal(got, want) {
		t.Fatalf("results = %v, want %v", got, want)
	}
	if got, want := len(testScanner.ipv4Conn.sentProbes()), 4; got != want {
		t.Fatalf("%d probes sent, want %d", got, want)
	}
}

func TestScanRejectsOneScanAtATime(t *testing.T) {
	t.Parallel()

	testScanner := newTestScanner(t, port_scanner_config.WithConcurrency(1), port_scanner_config.WithTimeout(time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- testScanner.scanner.Scan(ctx, []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")}, []int{80})
	}()

	// Wait for the first scan to be under way.
	deadline := time.Now().Add(2 * time.Second)
	for len(testScanner.ipv4Conn.sentProbes()) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the first scan never started")
		}
		time.Sleep(time.Millisecond)
	}

	err := testScanner.scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.1/32")}, []int{80})
	if !errors.Is(err, portScannerErrors.ErrScanInProgress) {
		t.Fatalf("second Scan() error = %v, want %v", err, portScannerErrors.ErrScanInProgress)
	}

	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first Scan() error = %v, want %v", err, context.Canceled)
	}
}

func TestScanValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		networks []*net.IPNet
		ports    []int
		options  []port_scanner_config.Option
		wantErr  error
	}{
		{name: "no networks", ports: []int{80}, wantErr: altshiftErrors.ErrValidationError},
		{name: "no ports", networks: []*net.IPNet{mustParseCidr(t, "192.0.2.1/32")}, wantErr: altshiftErrors.ErrValidationError},
		{
			name:     "bad port",
			networks: []*net.IPNet{mustParseCidr(t, "192.0.2.1/32")},
			ports:    []int{70000},
			wantErr:  portScannerErrors.ErrInvalidPort,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testScanner := newTestScanner(t, testCase.options...)
			err := testScanner.scanner.Scan(context.Background(), testCase.networks, testCase.ports)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("Scan() error = %v, want %v", err, testCase.wantErr)
			}
			if sent := len(testScanner.ipv4Conn.sentProbes()); sent != 0 {
				t.Fatalf("%d probes sent, want none", sent)
			}
		})
	}
}

func TestScanRejectsIpv6TargetsWithoutIpv6Socket(t *testing.T) {
	t.Parallel()

	testScanner := newTestScanner(t)
	testScanner.scanner.listenHandler.TcpIpv6Connection = nil

	err := testScanner.scanner.Scan(
		context.Background(),
		[]*net.IPNet{mustParseCidr(t, "192.0.2.1/32"), mustParseCidr(t, "2001:db8::1/128")},
		[]int{80},
	)
	if !errors.Is(err, altshiftErrors.ErrValidationError) {
		t.Fatalf("Scan() error = %v, want a validation error", err)
	}
	if sent := len(testScanner.ipv4Conn.sentProbes()); sent != 0 {
		t.Fatalf("%d probes sent, want none: the mismatch should be caught before any probe goes out", sent)
	}
}

func TestNewScannerValidation(t *testing.T) {
	t.Parallel()

	listenHandler := &listener_handler.ListenHandler{ListenPort: testListenPort, TcpIpv4Connection: &fakePacketConn{}}
	callback := func(*Result) {}
	source := newFakePacketSource(layers.LinkTypeEthernet)
	t.Cleanup(source.close)

	// The largest int; beyond a sequence number on 64-bit platforms, where the case applies.
	beyondSequenceNumber := math.MaxInt

	testCases := []struct {
		name          string
		listenHandler *listener_handler.ListenHandler
		sources       []PacketSource
		callback      func(*Result)
		options       []port_scanner_config.Option
		wantNilError  bool
		wantErr       error
	}{
		{name: "nil listen handler", sources: []PacketSource{source}, callback: callback, wantNilError: true},
		{name: "nil callback", listenHandler: listenHandler, sources: []PacketSource{source}, wantNilError: true},
		{name: "nil packet source", listenHandler: listenHandler, sources: []PacketSource{nil}, callback: callback, wantNilError: true},
		{
			name:          "listen port zero",
			listenHandler: &listener_handler.ListenHandler{TcpIpv4Connection: &fakePacketConn{}},
			sources:       []PacketSource{source}, callback: callback,
			wantErr: portScannerErrors.ErrInvalidPort,
		},
		{
			name: "zero concurrency", listenHandler: listenHandler, sources: []PacketSource{source}, callback: callback,
			options: []port_scanner_config.Option{port_scanner_config.WithConcurrency(0)},
			wantErr: portScannerErrors.ErrConcurrencyOutOfRange,
		},
		{
			name: "negative concurrency", listenHandler: listenHandler, sources: []PacketSource{source}, callback: callback,
			options: []port_scanner_config.Option{port_scanner_config.WithConcurrency(-1)},
			wantErr: portScannerErrors.ErrConcurrencyOutOfRange,
		},
		{
			name: "concurrency beyond a sequence number", listenHandler: listenHandler, sources: []PacketSource{source}, callback: callback,
			options: []port_scanner_config.Option{port_scanner_config.WithConcurrency(beyondSequenceNumber)},
			wantErr: portScannerErrors.ErrConcurrencyOutOfRange,
		},
		{
			name: "zero timeout", listenHandler: listenHandler, sources: []PacketSource{source}, callback: callback,
			options: []port_scanner_config.Option{port_scanner_config.WithTimeout(0)},
			wantErr: portScannerErrors.ErrTimeoutOutOfRange,
		},
		{
			name: "zero send attempts", listenHandler: listenHandler, sources: []PacketSource{source}, callback: callback,
			options: []port_scanner_config.Option{port_scanner_config.WithSendAttempts(0)},
			wantErr: portScannerErrors.ErrSendAttemptsOutOfRange,
		},
		{
			name: "negative retry wait", listenHandler: listenHandler, sources: []PacketSource{source}, callback: callback,
			options: []port_scanner_config.Option{port_scanner_config.WithSendRetryWait(-time.Second)},
			wantErr: portScannerErrors.ErrTimeoutOutOfRange,
		},
		{name: "no packet sources is allowed", listenHandler: listenHandler, callback: callback},
		{name: "valid", listenHandler: listenHandler, sources: []PacketSource{source}, callback: callback},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if testCase.name == "concurrency beyond a sequence number" && uint64(math.MaxInt) <= math.MaxUint32 {
				t.Skip("int cannot exceed a sequence number on this platform")
			}

			scanner, err := NewScanner(testCase.listenHandler, testCase.sources, testCase.callback, testCase.options...)
			switch {
			case testCase.wantNilError:
				if _, ok := errors.AsType[*nil_error.Error](err); !ok {
					t.Fatalf("NewScanner() error = %v, want a nil error", err)
				}
			case testCase.wantErr != nil:
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("NewScanner() error = %v, want %v", err, testCase.wantErr)
				}
				if !errors.Is(err, altshiftErrors.ErrValidationError) {
					t.Fatalf("NewScanner() error = %v, want a validation error", err)
				}
			default:
				if err != nil {
					t.Fatalf("NewScanner() error = %v", err)
				}
				if scanner == nil {
					t.Fatalf("NewScanner() = nil")
				}
			}
		})
	}
}

func TestNilScanner(t *testing.T) {
	t.Parallel()

	var scanner *Scanner
	if _, ok := errors.AsType[*nil_error.Error](scanner.Scan(context.Background(), nil, nil)); !ok {
		t.Fatalf("(*Scanner)(nil).Scan() did not return a nil error")
	}
}

func TestConsumeReplyNil(t *testing.T) {
	t.Parallel()

	testScanner := newTestScanner(t)
	testScanner.scanner.consumeReply(context.Background(), nil)
}

func TestScanCallbacksFinishBeforeReturn(t *testing.T) {
	t.Parallel()

	var inFlight atomic.Int32
	var finished atomic.Int32

	source := newFakePacketSource(layers.LinkTypeEthernet)
	t.Cleanup(source.close)
	ipv4Conn := &fakePacketConn{}
	listenHandler := &listener_handler.ListenHandler{ListenPort: testListenPort, TcpIpv4Connection: ipv4Conn}

	scanner, err := NewScanner(
		listenHandler,
		[]PacketSource{source},
		func(*Result) {
			inFlight.Add(1)
			time.Sleep(20 * time.Millisecond)
			inFlight.Add(-1)
			finished.Add(1)
		},
		port_scanner_config.WithTimeout(testTimeout),
	)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	scanner.resolveSourceIp = fixedSourceIp(testSourceIp)
	ipv4Conn.onSend = func(probe *sentProbe) {
		source.inject(synAckFor(t, probe, layers.LinkTypeEthernet))
	}

	if err := scanner.Scan(context.Background(), []*net.IPNet{mustParseCidr(t, "192.0.2.0/29")}, []int{80}); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if got := inFlight.Load(); got != 0 {
		t.Fatalf("%d callbacks still running after Scan() returned", got)
	}
	if got, want := finished.Load(), int32(8); got != want {
		t.Fatalf("%d callbacks finished, want %d", got, want)
	}
}
