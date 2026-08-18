package port_scanner

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
	"github.com/altshiftab/port_scanner/pkg/port_scanner/port_scanner_config"
)

func TestParseTargets(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		targets []string
		want    []string
		wantErr error
	}{
		{name: "none", targets: nil, want: []string{}},
		{name: "empty strings are skipped", targets: []string{"", ""}, want: []string{}},
		{name: "ipv4 address", targets: []string{"192.0.2.1"}, want: []string{"192.0.2.1/32"}},
		{name: "ipv4 network", targets: []string{"192.0.2.0/24"}, want: []string{"192.0.2.0/24"}},
		{name: "ipv4 network with host bits", targets: []string{"192.0.2.77/24"}, want: []string{"192.0.2.0/24"}},
		{name: "ipv6 address", targets: []string{"2001:db8::1"}, want: []string{"2001:db8::1/128"}},
		{name: "ipv6 network", targets: []string{"2001:db8::/120"}, want: []string{"2001:db8::/120"}},
		{
			name:    "mixed",
			targets: []string{"192.0.2.1", "", "2001:db8::/120"},
			want:    []string{"192.0.2.1/32", "2001:db8::/120"},
		},
		{name: "host name", targets: []string{"example.com"}, wantErr: altshiftErrors.ErrParseError},
		{name: "garbage", targets: []string{"192.0.2.0/33"}, wantErr: altshiftErrors.ErrParseError},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			networks, err := ParseTargets(testCase.targets)
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("ParseTargets() error = %v, want %v", err, testCase.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseTargets() error = %v", err)
			}

			got := make([]string, 0, len(networks))
			for _, network := range networks {
				got = append(got, network.String())
			}
			if !slices.Equal(got, testCase.want) {
				t.Fatalf("ParseTargets() = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestIsPrivileged(t *testing.T) {
	t.Parallel()

	// Root is always privileged; anything else depends on the capabilities the test was given,
	// so only the root case has a known answer. Either way it must not fail.
	got := IsPrivileged()
	if os.Geteuid() == 0 && !got {
		t.Fatalf("IsPrivileged() = false as root")
	}

	if _, err := effectiveCapabilities(); err != nil {
		t.Fatalf("effectiveCapabilities() error = %v", err)
	}
}

func TestScanNetworksValidation(t *testing.T) {
	t.Parallel()

	callback := func(*Result) {}

	testCases := []struct {
		name         string
		networks     []*net.IPNet
		ports        []int
		callback     func(*Result)
		options      []port_scanner_config.Option
		wantErr      error
		wantNilError bool
	}{
		{name: "no networks", ports: []int{80}, callback: callback, wantErr: altshiftErrors.ErrValidationError},
		{name: "no ports", networks: []*net.IPNet{mustParseCidr(t, "192.0.2.1/32")}, callback: callback, wantErr: altshiftErrors.ErrValidationError},
		{name: "nil callback", networks: []*net.IPNet{mustParseCidr(t, "192.0.2.1/32")}, ports: []int{80}, wantNilError: true},
		{
			name: "bad concurrency", networks: []*net.IPNet{mustParseCidr(t, "192.0.2.1/32")}, ports: []int{80}, callback: callback,
			options: []port_scanner_config.Option{port_scanner_config.WithConcurrency(0)},
			wantErr: portScannerErrors.ErrConcurrencyOutOfRange,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := ScanNetworks(context.Background(), testCase.networks, testCase.ports, testCase.callback, testCase.options...)
			if testCase.wantNilError {
				if _, ok := errors.AsType[*nil_error.Error](err); !ok {
					t.Fatalf("ScanNetworks() error = %v, want a nil error", err)
				}
				return
			}
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("ScanNetworks() error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

func TestScanRejectsUnparsableTargets(t *testing.T) {
	t.Parallel()

	err := Scan(context.Background(), []string{"not-an-address"}, []int{80}, func(*Result) {})
	if !errors.Is(err, altshiftErrors.ErrParseError) {
		t.Fatalf("Scan() error = %v, want %v", err, altshiftErrors.ErrParseError)
	}
}

// TestScanEndToEnd sends real probes to the loopback interface: a listener is opened on one port and
// that port, and only that port, must be reported open. It needs CAP_NET_RAW and is skipped
// without it; run the tests as root to exercise it.
func TestScanEndToEnd(t *testing.T) {
	t.Parallel()

	if !IsPrivileged() {
		t.Skip("sending probes needs CAP_NET_RAW; run with it to exercise a real scan")
	}

	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = listener.Close() }()

	openPort := listener.Addr().(*net.TCPAddr).Port

	// A port that nothing listens on: reserve one and close it again.
	closedListener, err := listenConfig.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	closedPort := closedListener.Addr().(*net.TCPAddr).Port
	_ = closedListener.Close()

	collector := &resultCollector{}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = Scan(
		ctx,
		[]string{"127.0.0.1"},
		[]int{openPort, closedPort},
		collector.callback,
		port_scanner_config.WithSkipIpv6(true),
		port_scanner_config.WithInterfaceNames("lo"),
		port_scanner_config.WithTimeout(2*time.Second),
	)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	want := []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(openPort))}
	if got := resultKeys(collector.all()); !slices.Equal(got, want) {
		t.Fatalf("results = %v, want %v", got, want)
	}
}
