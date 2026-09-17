package port_scanner

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/altshiftab/port_scanner/pkg/port_scanner/port_scanner_config"
)

// TestScanConnectReportsCancellationMidScan covers the case the cancelled-before-starting test does
// not: a context that ends while the dials are in flight.
//
// It is the case that matters in production. A scan runs inside a request with a deadline, and a
// deadline that arrives turns every outstanding dial into a failure, which a connect scan reads as
// "not open". Returning nil there reports a clean scan that found nothing, which is the one wrong
// answer nobody downstream can detect: an entity's open ports would silently disappear.
func TestScanConnectReportsCancellationMidScan(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())

	// Dark space, so every dial hangs until its timeout rather than being refused.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := Scan(
		ctx,
		[]string{"192.0.2.0/30"},
		[]int{80, 443},
		func(*Result) {},
		port_scanner_config.WithMode(port_scanner_config.ModeConnect),
		port_scanner_config.WithConcurrency(64),
		port_scanner_config.WithConnectTimeout(10*time.Second),
	)

	if err == nil {
		t.Fatal("a scan cancelled while dialling returned nil, reporting a clean scan that found nothing")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to wrap context.Canceled", err)
	}
}

// TestScanConnectReportsDeadline is the same failure arriving as a deadline rather than a cancel,
// which is the shape a request timeout actually takes.
func TestScanConnectReportsDeadline(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	err := Scan(
		ctx,
		[]string{"192.0.2.0/30"},
		[]int{80, 443},
		func(*Result) {},
		port_scanner_config.WithMode(port_scanner_config.ModeConnect),
		port_scanner_config.WithConcurrency(64),
		port_scanner_config.WithConnectTimeout(10*time.Second),
	)

	if err == nil {
		t.Fatal("a scan whose deadline passed returned nil, reporting a clean scan that found nothing")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want it to wrap context.DeadlineExceeded", err)
	}
}

// TestExpandNetworksAcceptsSixteenByteIpv4 covers an IPNet built by hand rather than by ParseCIDR.
//
// net.ParseIP returns a 16-byte value for an IPv4 address, and net.CIDRMask(32, 32) a 4-byte mask.
// That pairing is what anyone assembling an IPNet in code produces, and ScanNetworks is exported,
// so it is a shape the package is asked to handle. SYN mode normalises it; connect mode has to
// agree, or the same target is scanned by one mode and silently skipped by the other.
func TestExpandNetworksAcceptsSixteenByteIpv4(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		network *net.IPNet
		want    []string
	}{
		{
			name:    "a sixteen-byte address with a four-byte mask",
			network: &net.IPNet{IP: net.ParseIP("192.0.2.7"), Mask: net.CIDRMask(32, 32)},
			want:    []string{"192.0.2.7"},
		},
		{
			name:    "a sixteen-byte address with a sixteen-byte mask",
			network: &net.IPNet{IP: net.ParseIP("192.0.2.7"), Mask: net.CIDRMask(128, 128)},
			want:    []string{"192.0.2.7"},
		},
		{
			name:    "a sixteen-byte network with a four-byte mask",
			network: &net.IPNet{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(30, 32)},
			want:    []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			name:    "a four-byte address, which already worked",
			network: &net.IPNet{IP: net.ParseIP("192.0.2.7").To4(), Mask: net.CIDRMask(32, 32)},
			want:    []string{"192.0.2.7"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			addresses, err := expandNetworks([]*net.IPNet{testCase.network}, false)
			if err != nil {
				t.Fatalf("expandNetworks: %v", err)
			}

			got := make([]string, 0, len(addresses))
			for _, address := range addresses {
				got = append(got, address.String())
			}

			if len(got) != len(testCase.want) {
				t.Fatalf("expandNetworks returned %v, want %v", got, testCase.want)
			}

			for index := range got {
				if got[index] != testCase.want[index] {
					t.Errorf("address %d = %q, want %q", index, got[index], testCase.want[index])
				}
			}
		})
	}
}

// TestScanNetworksAgreesBetweenAddressForms is the same defect seen from outside: a scan of a host
// that is genuinely listening must find it whichever way the IPNet was built.
func TestScanNetworksAgreesBetweenAddressForms(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	openPort := listener.Addr().(*net.TCPAddr).Port

	testCases := []struct {
		name    string
		network *net.IPNet
	}{
		{
			name:    "four-byte address",
			network: &net.IPNet{IP: net.ParseIP("127.0.0.1").To4(), Mask: net.CIDRMask(32, 32)},
		},
		{
			name:    "sixteen-byte address",
			network: &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(32, 32)},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var mutex sync.Mutex
			var found []*Result

			err := ScanNetworks(
				t.Context(),
				[]*net.IPNet{testCase.network},
				[]int{openPort},
				func(result *Result) {
					mutex.Lock()
					defer mutex.Unlock()
					found = append(found, result)
				},
				port_scanner_config.WithMode(port_scanner_config.ModeConnect),
				port_scanner_config.WithConnectTimeout(2*time.Second),
			)
			if err != nil {
				t.Fatalf("ScanNetworks: %v", err)
			}

			mutex.Lock()
			defer mutex.Unlock()

			if len(found) != 1 {
				t.Fatalf("found %d open ports, want 1 -- the address form changed the answer", len(found))
			}
		})
	}
}

// TestIncrementAddress covers the wrap the enumeration loop relies on to terminate.
func TestIncrementAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		address    string
		expect     string
		expectMore bool
	}{
		{name: "an ordinary address", address: "192.0.2.1", expect: "192.0.2.2", expectMore: true},
		{name: "across an octet", address: "192.0.2.255", expect: "192.0.3.0", expectMore: true},
		{name: "the last address wraps", address: "255.255.255.255", expect: "0.0.0.0", expectMore: false},
		{name: "ipv6", address: "2001:db8::ff", expect: "2001:db8::100", expectMore: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			address := net.ParseIP(testCase.address)
			if address.To4() != nil {
				address = address.To4()
			}

			more := incrementAddress(address)

			if address.String() != testCase.expect {
				t.Errorf("incrementAddress produced %q, want %q", address.String(), testCase.expect)
			}

			if more != testCase.expectMore {
				t.Errorf("incrementAddress reported more = %v, want %v", more, testCase.expectMore)
			}
		})
	}
}
