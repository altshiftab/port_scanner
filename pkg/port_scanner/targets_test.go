package port_scanner

import (
	"errors"
	"net"
	"reflect"
	"slices"
	"strconv"
	"testing"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
)

func mustParseCidr(t *testing.T, cidr string) *net.IPNet {
	t.Helper()

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("net.ParseCIDR(%q) error = %v", cidr, err)
	}

	return network
}

func TestNewTargetSpaceValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		networks []*net.IPNet
		ports    []int
		wantErr  error
	}{
		{
			name:    "no networks",
			ports:   []int{80},
			wantErr: altshiftErrors.ErrValidationError,
		},
		{
			name:     "no ports",
			networks: []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")},
			wantErr:  altshiftErrors.ErrValidationError,
		},
		{
			name:     "nil network",
			networks: []*net.IPNet{nil},
			ports:    []int{80},
			wantErr:  altshiftErrors.ErrValidationError,
		},
		{
			name:     "port zero",
			networks: []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")},
			ports:    []int{80, 0},
			wantErr:  portScannerErrors.ErrInvalidPort,
		},
		{
			name:     "port too large",
			networks: []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")},
			ports:    []int{65536},
			wantErr:  portScannerErrors.ErrInvalidPort,
		},
		{
			name:     "ipv6 network too large",
			networks: []*net.IPNet{mustParseCidr(t, "2001:db8::/32")},
			ports:    []int{80},
			wantErr:  portScannerErrors.ErrTooManyTargets,
		},
		{
			name:     "ipv6 network at the limit",
			networks: []*net.IPNet{mustParseCidr(t, "2001:db8::/66")},
			ports:    []int{80},
		},
		{
			name:     "sum overflows",
			networks: []*net.IPNet{mustParseCidr(t, "2001:db8::/66"), mustParseCidr(t, "2001:db8:1::/66")},
			ports:    []int{80, 443},
			wantErr:  portScannerErrors.ErrTooManyTargets,
		},
		{
			name:     "non-canonical mask",
			networks: []*net.IPNet{{IP: net.IPv4(192, 0, 2, 0).To4(), Mask: net.IPMask{255, 0, 255, 0}}},
			ports:    []int{80},
			wantErr:  portScannerErrors.ErrInvalidNetworkMask,
		},
		{
			name:     "mask length that fits neither family",
			networks: []*net.IPNet{{IP: net.IPv4(192, 0, 2, 0).To4(), Mask: net.CIDRMask(8, 24)}},
			ports:    []int{80},
			wantErr:  portScannerErrors.ErrInvalidNetworkMask,
		},
		{
			name:     "ipv6 address with ipv4 mask",
			networks: []*net.IPNet{{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(24, 32)}},
			ports:    []int{80},
			wantErr:  portScannerErrors.ErrInvalidNetworkMask,
		},
		{
			name:     "valid",
			networks: []*net.IPNet{mustParseCidr(t, "192.0.2.0/24"), mustParseCidr(t, "2001:db8::/120")},
			ports:    []int{80, 443},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			space, err := newTargetSpace(testCase.networks, testCase.ports)
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("newTargetSpace() error = %v, want %v", err, testCase.wantErr)
				}
				if !errors.Is(err, altshiftErrors.ErrValidationError) {
					t.Fatalf("newTargetSpace() error = %v, want a validation error", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("newTargetSpace() error = %v", err)
			}
			if space == nil {
				t.Fatalf("newTargetSpace() = nil")
			}
		})
	}
}

func TestNewTargetSpaceDeduplicatesPorts(t *testing.T) {
	t.Parallel()

	space, err := newTargetSpace([]*net.IPNet{mustParseCidr(t, "192.0.2.1/32")}, []int{443, 80, 443, 22, 80})
	if err != nil {
		t.Fatalf("newTargetSpace() error = %v", err)
	}

	if want := []int{22, 80, 443}; !reflect.DeepEqual(space.ports, want) {
		t.Fatalf("ports = %v, want %v", space.ports, want)
	}
	if got, want := space.Size(), uint64(3); got != want {
		t.Fatalf("Size() = %d, want %d", got, want)
	}
}

// TestTargetCoversEverything checks that the target indices 0..Size()-1 map onto every (address,
// port) pair exactly once, across networks of different sizes and families. The second network being
// larger than everything before it is what a modulo in place of a subtraction gets wrong.
func TestTargetCoversEverything(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		networks []string
		ports    []int
	}{
		{name: "single address", networks: []string{"192.0.2.1/32"}, ports: []int{80}},
		{name: "single network", networks: []string{"192.0.2.0/29"}, ports: []int{80, 443}},
		{name: "small then large", networks: []string{"192.0.2.1/32", "198.51.100.0/28"}, ports: []int{80}},
		{name: "large then small", networks: []string{"198.51.100.0/28", "192.0.2.1/32"}, ports: []int{80}},
		{
			name:     "many mixed",
			networks: []string{"192.0.2.1/32", "198.51.100.0/30", "203.0.113.0/28", "2001:db8::/126", "192.0.2.2/32"},
			ports:    []int{22, 80, 443},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			networks := make([]*net.IPNet, 0, len(testCase.networks))
			for _, cidr := range testCase.networks {
				networks = append(networks, mustParseCidr(t, cidr))
			}

			space, err := newTargetSpace(networks, testCase.ports)
			if err != nil {
				t.Fatalf("newTargetSpace() error = %v", err)
			}

			var wantSize uint64
			for _, network := range networks {
				ones, bitsCount := network.Mask.Size()
				wantSize += (uint64(1) << (bitsCount - ones)) * uint64(len(testCase.ports))
			}
			if got := space.Size(); got != wantSize {
				t.Fatalf("Size() = %d, want %d", got, wantSize)
			}

			seen := make(map[string]int)
			for index := range space.Size() {
				ip, port, networkIndex, err := space.Target(index)
				if err != nil {
					t.Fatalf("Target(%d) error = %v", index, err)
				}

				if networkIndex < 0 || networkIndex >= len(networks) {
					t.Fatalf("Target(%d) network index = %d, want one of %d networks", index, networkIndex, len(networks))
				}
				if !networks[networkIndex].Contains(ip) {
					t.Fatalf("Target(%d) = %v, not in network %d (%v)", index, ip, networkIndex, networks[networkIndex])
				}

				if !slices.Contains(testCase.ports, port) {
					t.Fatalf("Target(%d) port = %d, not among %v", index, port, testCase.ports)
				}

				seen[net.JoinHostPort(ip.String(), strconv.Itoa(port))]++
			}

			if got := uint64(len(seen)); got != wantSize {
				t.Fatalf("%d distinct targets, want %d", got, wantSize)
			}
			for target, count := range seen {
				if count != 1 {
					t.Fatalf("target %q produced %d times", target, count)
				}
			}
		})
	}
}

func TestTargetOutOfRange(t *testing.T) {
	t.Parallel()

	space, err := newTargetSpace([]*net.IPNet{mustParseCidr(t, "192.0.2.0/30")}, []int{80})
	if err != nil {
		t.Fatalf("newTargetSpace() error = %v", err)
	}

	if _, _, _, err := space.Target(space.Size()); err == nil {
		t.Fatalf("Target(Size()) error = nil, want an error")
	}
}

func TestNthAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		network string
		n       uint64
		want    string
		wantErr bool
	}{
		{name: "first ipv4", network: "192.0.2.0/24", n: 0, want: "192.0.2.0"},
		{name: "last ipv4", network: "192.0.2.0/24", n: 255, want: "192.0.2.255"},
		{name: "ipv4 crossing an octet", network: "10.0.0.0/8", n: 256, want: "10.0.1.0"},
		{name: "ipv4 with leading zero octet", network: "0.0.0.0/8", n: 5, want: "0.0.0.5"},
		{name: "ipv4 overflow", network: "255.255.255.0/24", n: 256, wantErr: true},
		{name: "first ipv6", network: "2001:db8::/120", n: 0, want: "2001:db8::"},
		{name: "ipv6 with leading zeros", network: "::/120", n: 1, want: "::1"},
		{name: "ipv6 crossing the low word", network: "2001:db8::/80", n: 1 << 40, want: "2001:db8::100:0:0"},
		{name: "ipv6 carry into the high word", network: "2001:db8:0:0:ffff:ffff:ffff:ff00/120", n: 256, wantErr: false, want: "2001:db8:0:1::"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			network, _, err := normalizeNetwork(mustParseCidr(t, testCase.network))
			if err != nil {
				t.Fatalf("normalizeNetwork() error = %v", err)
			}

			got, err := nthAddress(network, testCase.n)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("nthAddress() = %v, want an error", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("nthAddress() error = %v", err)
			}
			if got.String() != testCase.want {
				t.Fatalf("nthAddress() = %v, want %v", got, testCase.want)
			}
			if wantLen := len(network.IP); len(got) != wantLen {
				t.Fatalf("nthAddress() has %d bytes, want %d", len(got), wantLen)
			}
		})
	}
}

func TestNthAddressRejectsBadInput(t *testing.T) {
	t.Parallel()

	if _, err := nthAddress(nil, 0); err == nil {
		t.Fatalf("nthAddress(nil) error = nil")
	}

	if _, err := nthAddress(&net.IPNet{IP: net.IP{1, 2, 3}}, 0); err == nil {
		t.Fatalf("nthAddress(three-byte ip) error = nil")
	}
}
