package port_scanner

import (
	"context"
	"errors"
	"testing"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/gopacket/gopacket/pcap"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
)

func TestReplyFilter(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		port int
		want string
	}{
		{name: "low port", port: 80, want: "tcp and dst port 80"},
		{name: "high port", port: 65535, want: "tcp and dst port 65535"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := ReplyFilter(testCase.port); got != testCase.want {
				t.Fatalf("ReplyFilter(%d) = %q, want %q", testCase.port, got, testCase.want)
			}
		})
	}
}

func TestOpenPcapHandleValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		interfaceName string
		bpfFilter     string
	}{
		{name: "empty interface name", interfaceName: "", bpfFilter: "tcp"},
		{name: "empty filter", interfaceName: "lo", bpfFilter: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			handle, err := OpenPcapHandle(testCase.interfaceName, testCase.bpfFilter)
			if handle != nil {
				handle.Close()
			}
			if _, ok := errors.AsType[*empty_error.Error](err); !ok {
				t.Fatalf("OpenPcapHandle() error = %v, want an empty error", err)
			}
		})
	}
}

func TestOpenPcapHandlesValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		listenPort     int
		interfaceNames []string
		wantErr        error
	}{
		{name: "port zero", listenPort: 0, wantErr: portScannerErrors.ErrInvalidPort},
		{name: "port too large", listenPort: 70000, wantErr: portScannerErrors.ErrInvalidPort},
		{
			name:           "unknown interface",
			listenPort:     40000,
			interfaceNames: []string{"no-such-interface-0"},
			wantErr:        portScannerErrors.ErrInterfaceNotUp,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			handles, err := OpenPcapHandles(context.Background(), testCase.listenPort, testCase.interfaceNames)
			ClosePcapHandles(handles)

			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("OpenPcapHandles() error = %v, want %v", err, testCase.wantErr)
			}
			if !errors.Is(err, altshiftErrors.ErrValidationError) {
				t.Fatalf("OpenPcapHandles() error = %v, want a validation error", err)
			}
		})
	}
}

func TestOpenPcapHandles(t *testing.T) {
	t.Parallel()

	if !IsPrivileged() {
		t.Skip("packet capture needs CAP_NET_RAW; run with it to exercise OpenPcapHandles")
	}

	handles, err := OpenPcapHandles(context.Background(), 40000, []string{"lo"})
	if err != nil {
		t.Fatalf("OpenPcapHandles() error = %v", err)
	}
	defer ClosePcapHandles(handles)

	if len(handles) != 1 {
		t.Fatalf("%d handles, want 1", len(handles))
	}
}

func TestClosePcapHandlesTolerantOfNil(t *testing.T) {
	t.Parallel()

	ClosePcapHandles(nil)
	ClosePcapHandles([]*pcap.Handle{nil})
}
