package port_scanner

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func TestOpenPcapHandleRejectsIncompleteArguments(t *testing.T) {
	t.Parallel()

	filter, err := ReplyFilter(44444)
	if err != nil {
		t.Fatalf("ReplyFilter: %v", err)
	}

	testCases := []struct {
		name          string
		interfaceName string
		useFilter     bool
	}{
		{name: "an empty interface name is rejected", interfaceName: "", useFilter: true},
		{name: "an empty filter is rejected", interfaceName: "lo", useFilter: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var handle *CaptureHandle
			var err error

			if testCase.useFilter {
				handle, err = OpenPcapHandle(testCase.interfaceName, filter)
			} else {
				handle, err = OpenPcapHandle(testCase.interfaceName, nil)
			}

			if err == nil {
				if handle != nil {
					_ = handle.Close()
				}
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

// The link type decides how a captured frame is decoded, and pcapgo does not
// report it, so it is derived from the interface.
func TestInterfaceLinkType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		networkInterface *net.Interface
		want             layers.LinkType
	}{
		{
			name:             "a nil interface falls back to ethernet",
			networkInterface: nil,
			want:             layers.LinkTypeEthernet,
		},
		{
			// Linux gives loopback frames a placeholder Ethernet header even
			// though the interface carries no hardware address.
			name:             "loopback is framed as ethernet",
			networkInterface: &net.Interface{Flags: net.FlagUp | net.FlagLoopback},
			want:             layers.LinkTypeEthernet,
		},
		{
			name: "an interface with a mac address is ethernet",
			networkInterface: &net.Interface{
				Flags:        net.FlagUp,
				HardwareAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5},
			},
			want: layers.LinkTypeEthernet,
		},
		{
			name:             "a tunnel carries bare ip",
			networkInterface: &net.Interface{Flags: net.FlagUp | net.FlagPointToPoint},
			want:             linkTypeDltRaw,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := interfaceLinkType(testCase.networkInterface); got != testCase.want {
				t.Errorf("interfaceLinkType() = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestClosePcapHandlesToleratesNil(t *testing.T) {
	t.Parallel()

	ClosePcapHandles(nil)
	ClosePcapHandles([]*CaptureHandle{nil})
	ClosePcapHandles([]*CaptureHandle{nil, nil})
}
