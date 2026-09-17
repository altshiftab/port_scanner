package port_scanner

import (
	"context"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/altshiftab/port_scanner/pkg/port_scanner/port_scanner_config"
)

func TestExpandNetworks(t *testing.T) {
	t.Parallel()

	mustNetwork := func(t *testing.T, cidr string) *net.IPNet {
		t.Helper()
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("net.ParseCIDR(%q): %v", cidr, err)
		}
		return network
	}

	testCases := []struct {
		name     string
		cidrs    []string
		skipIpv6 bool
		want     []string
	}{
		{
			name:  "a /32 is a single host",
			cidrs: []string{"192.0.2.7/32"},
			want:  []string{"192.0.2.7"},
		},
		{
			// Both addresses of a point-to-point link are hosts.
			name:  "a /31 keeps both addresses",
			cidrs: []string{"192.0.2.0/31"},
			want:  []string{"192.0.2.0", "192.0.2.1"},
		},
		{
			name:  "a /30 drops the network and broadcast addresses",
			cidrs: []string{"192.0.2.0/30"},
			want:  []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			name:  "a /29 keeps the six usable hosts",
			cidrs: []string{"192.0.2.0/29"},
			want: []string{
				"192.0.2.1", "192.0.2.2", "192.0.2.3",
				"192.0.2.4", "192.0.2.5", "192.0.2.6",
			},
		},
		{
			name:     "ipv6 is left out when asked",
			cidrs:    []string{"192.0.2.0/31", "2001:db8::/127"},
			skipIpv6: true,
			want:     []string{"192.0.2.0", "192.0.2.1"},
		},
		{
			name:  "ipv6 is enumerated when not skipped",
			cidrs: []string{"2001:db8::/127"},
			want:  []string{"2001:db8::", "2001:db8::1"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			networks := make([]*net.IPNet, 0, len(testCase.cidrs))
			for _, cidr := range testCase.cidrs {
				networks = append(networks, mustNetwork(t, cidr))
			}

			addresses, err := expandNetworks(networks, testCase.skipIpv6)
			if err != nil {
				t.Fatalf("expandNetworks: %v", err)
			}

			got := make([]string, 0, len(addresses))
			for _, address := range addresses {
				got = append(got, address.String())
			}

			slices.Sort(got)
			want := slices.Clone(testCase.want)
			slices.Sort(want)

			if !slices.Equal(got, want) {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

// A mistyped prefix should be an error rather than a scan that never ends.
func TestExpandNetworksRejectsAnEnormousRange(t *testing.T) {
	t.Parallel()

	_, network, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("net.ParseCIDR: %v", err)
	}

	if _, err := expandNetworks([]*net.IPNet{network}, false); err == nil {
		t.Fatal("expected a /8 to be rejected, got nil")
	}
}

// The point of the connect mode is that it runs without CAP_NET_RAW, so this
// exercises a real scan against a real listener as an ordinary user.
func TestScanConnectFindsAListener(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	openPort := listener.Addr().(*net.TCPAddr).Port

	// A port that was bound and released is almost certainly closed.
	closedListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := closedListener.Addr().(*net.TCPAddr).Port
	_ = closedListener.Close()

	// The callback runs on a goroutine per result, so the collection is guarded even though only
	// one result is expected here: an unguarded append is a race whether or not it happens to be
	// contended on the day.
	var mutex sync.Mutex
	var found []*Result
	err = Scan(
		t.Context(),
		[]string{"127.0.0.1"},
		[]int{openPort, closedPort},
		func(result *Result) {
			mutex.Lock()
			defer mutex.Unlock()
			found = append(found, result)
		},
		port_scanner_config.WithMode(port_scanner_config.ModeConnect),
		port_scanner_config.WithConcurrency(8),
		port_scanner_config.WithConnectTimeout(time.Second),
	)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(found) != 1 {
		t.Fatalf("found %d open ports, want 1 (%+v)", len(found), found)
	}
	if found[0].Port != openPort {
		t.Errorf("found port %d, want %d", found[0].Port, openPort)
	}
	if found[0].Transport != "tcp" {
		t.Errorf("Transport = %q, want %q", found[0].Transport, "tcp")
	}
	if found[0].IpVersion != ipv4Version {
		t.Errorf("IpVersion = %d, want %d", found[0].IpVersion, ipv4Version)
	}
}

func TestScanConnectReportsACancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := Scan(
		ctx,
		[]string{"192.0.2.0/24"},
		[]int{80, 443},
		func(*Result) {},
		port_scanner_config.WithMode(port_scanner_config.ModeConnect),
	)
	if err == nil {
		t.Fatal("expected an error for a cancelled context, got nil")
	}
}
