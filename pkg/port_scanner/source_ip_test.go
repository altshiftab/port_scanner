package port_scanner

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

var errNoRoute = errors.New("no route")

func TestKernelSourceIp(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		destination string
		want        string
		wantLen     int
	}{
		{name: "ipv4 loopback", destination: "127.0.0.1", want: "127.0.0.1", wantLen: net.IPv4len},
		{name: "ipv6 loopback", destination: "::1", want: "::1", wantLen: net.IPv6len},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := KernelSourceIp(net.ParseIP(testCase.destination))
			if err != nil {
				if testCase.wantLen == net.IPv6len {
					t.Skipf("KernelSourceIp() error = %v; IPv6 loopback is not available", err)
				}
				t.Fatalf("KernelSourceIp() error = %v", err)
			}

			if got.String() != testCase.want {
				t.Fatalf("KernelSourceIp() = %v, want %v", got, testCase.want)
			}
			if len(got) != testCase.wantLen {
				t.Fatalf("KernelSourceIp() has %d bytes, want %d", len(got), testCase.wantLen)
			}
		})
	}
}

func TestKernelSourceIpRejectsEmptyDestination(t *testing.T) {
	t.Parallel()

	if _, err := KernelSourceIp(nil); err == nil {
		t.Fatalf("KernelSourceIp(nil) error = nil")
	} else if _, ok := errors.AsType[*nil_error.Error](err); !ok {
		t.Fatalf("KernelSourceIp(nil) error = %v, want a nil error", err)
	}
}

func TestCachedSourceIpResolver(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	resolver := newCachedSourceIpResolver(func(destination net.IP) (net.IP, error) {
		calls.Add(1)
		if destination.Equal(net.ParseIP("192.0.2.66")) {
			return nil, errNoRoute
		}
		return net.ParseIP("192.0.2.1").To4(), nil
	})

	for range 3 {
		got, err := resolver.Resolve(net.ParseIP("192.0.2.10"))
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if got.String() != "192.0.2.1" {
			t.Fatalf("Resolve() = %v, want 192.0.2.1", got)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver called %d times for one destination, want 1", got)
	}

	// The four-byte and sixteen-byte forms of an address are the same cache entry.
	if _, err := resolver.Resolve(net.ParseIP("192.0.2.10").To4()); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver called %d times, want 1; the four-byte form missed the cache", got)
	}

	if _, err := resolver.Resolve(net.ParseIP("192.0.2.11")); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver called %d times for two destinations, want 2", got)
	}

	// Errors are not cached.
	for range 2 {
		if _, err := resolver.Resolve(net.ParseIP("192.0.2.66")); err == nil {
			t.Fatalf("Resolve() error = nil, want an error")
		}
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("resolver called %d times, want 4; a failure was cached", got)
	}
}

func TestCachedSourceIpResolverBound(t *testing.T) {
	t.Parallel()

	resolver := newCachedSourceIpResolver(func(net.IP) (net.IP, error) {
		return net.ParseIP("192.0.2.1").To4(), nil
	})

	// Fill the cache past its bound; it must stop growing but keep answering.
	for i := range maxSourceIpCacheSize + 100 {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		if _, err := resolver.Resolve(ip); err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
	}

	if got := len(resolver.entries); got != maxSourceIpCacheSize {
		t.Fatalf("cache holds %d entries, want %d", got, maxSourceIpCacheSize)
	}
}
