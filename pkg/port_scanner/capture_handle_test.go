package port_scanner

import (
	"net"
	"testing"
	"time"

	"github.com/altshiftab/utils_go/pkg/net/packet"
)

func TestOpenCaptureHandleRejectsIncompleteArguments(t *testing.T) {
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
				handle, err = OpenCaptureHandle(testCase.interfaceName, filter)
			} else {
				handle, err = OpenCaptureHandle(testCase.interfaceName, nil)
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

// openLoopbackCapture opens a capture handle on loopback for replies to port, or skips the test
// when packet sockets cannot be opened here.
func openLoopbackCapture(t *testing.T, port int) *CaptureHandle {
	t.Helper()

	if !IsPrivileged() {
		t.Skip("packet sockets need CAP_NET_RAW; run with it to exercise a capture handle")
	}

	filter, err := ReplyFilter(port)
	if err != nil {
		t.Fatalf("ReplyFilter: %v", err)
	}

	handle, err := OpenCaptureHandle("lo", filter)
	if err != nil {
		t.Fatalf("OpenCaptureHandle: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	return handle
}

// A capture handle hands over packets from the IP header on, and on loopback, where each packet is
// seen leaving as well as arriving, only once.
func TestCaptureHandleReadsNetworkLayerPackets(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		network string
		address string
		version int
	}{
		{name: "ipv4", network: "tcp4", address: "127.0.0.1:0", version: 4},
		{name: "ipv6", network: "tcp6", address: "[::1]:0", version: 6},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			listenConfig := net.ListenConfig{}
			listener, err := listenConfig.Listen(t.Context(), testCase.network, testCase.address)
			if err != nil {
				t.Skipf("net listen: %v", err)
			}
			defer func() { _ = listener.Close() }()

			tcpAddr, ok := listener.Addr().(*net.TCPAddr)
			if !ok {
				t.Fatalf("listener address is %T", listener.Addr())
			}

			// The filter keeps segments addressed to the port: the client's SYN and the ACK
			// completing the handshake, and nothing the listener sends back.
			handle := openLoopbackCapture(t, tcpAddr.Port)

			dialer := net.Dialer{}
			connection, err := dialer.DialContext(t.Context(), testCase.network, listener.Addr().String())
			if err != nil {
				t.Fatalf("net dial: %v", err)
			}
			defer func() { _ = connection.Close() }()

			var flags []packet.TcpFlags
			for range 2 {
				data, err := handle.ReadPacketData()
				if err != nil {
					t.Fatalf("ReadPacketData: %v", err)
				}

				ip, err := packet.ParseIp(data)
				if err != nil {
					t.Fatalf("ParseIp(%x): %v", data, err)
				}
				if ip.Version != testCase.version {
					t.Errorf("ip version = %d, want %d", ip.Version, testCase.version)
				}

				tcp, err := packet.ParseTcp(ip.Payload)
				if err != nil {
					t.Fatalf("ParseTcp: %v", err)
				}
				if int(tcp.DestinationPort) != tcpAddr.Port {
					t.Errorf("destination port = %d, want %d", tcp.DestinationPort, tcpAddr.Port)
				}

				flags = append(flags, tcp.Flags)
			}

			// Were each packet read as it left as well as when it arrived, the second read would be
			// the SYN again.
			// A SYN may also carry ECE and CWR, where the kernel asks for ECN.
			isSyn := flags[0].Has(packet.TcpFlagSyn) && !flags[0].Has(packet.TcpFlagAck)
			isAck := flags[1].Has(packet.TcpFlagAck) && !flags[1].Has(packet.TcpFlagSyn)
			if !isSyn || !isAck {
				t.Errorf("flags = %v, want a SYN and then an ACK", flags)
			}
		})
	}
}

// A read has no timeout, so closing the handle is the only way to wake a reader on a quiet
// interface, and the reader must be able to tell that from a failure.
func TestCaptureHandleCloseWakesReader(t *testing.T) {
	t.Parallel()

	handle := openLoopbackCapture(t, 9)

	readErr := make(chan error, 1)
	go func() {
		_, err := handle.ReadPacketData()
		readErr <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := handle.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-readErr:
		if err == nil {
			t.Error("ReadPacketData returned no error after Close")
		}
		if !handle.Closed() {
			t.Error("Closed() = false after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadPacketData was not woken by Close")
	}
}

func TestCloseCaptureHandlesToleratesNil(t *testing.T) {
	t.Parallel()

	CloseCaptureHandles(nil)
	CloseCaptureHandles([]*CaptureHandle{nil})
	CloseCaptureHandles([]*CaptureHandle{nil, nil})
}
