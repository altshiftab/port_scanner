package port_scanner

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/altshiftab/port_scanner/pkg/port_scanner/port_scanner_config"
	"github.com/altshiftab/port_scanner/pkg/types/listener_handler"
)

// blockingPacketSource models the real capture handle, which the fake in helpers_test.go does not.
//
// A pcapgo.EthernetHandle read parks in the runtime poller until a frame arrives or the handle is
// closed: it has no read deadline and it does not drain itself. A stand-in that returns after a few
// milliseconds of quiet hides every shutdown problem there is, because the reader it is feeding
// always finds its way out on its own.
type blockingPacketSource struct {
	packets chan []byte
	done    chan struct{}
	once    sync.Once
	closed  atomic.Bool

	// reading is closed once a read has actually blocked, so a test can wait for the reader to be
	// parked rather than guessing with a sleep.
	reading   chan struct{}
	readingOn sync.Once
}

func newBlockingPacketSource() *blockingPacketSource {
	return &blockingPacketSource{
		packets: make(chan []byte, 16),
		done:    make(chan struct{}),
		reading: make(chan struct{}),
	}
}

func (source *blockingPacketSource) Closed() bool { return source.closed.Load() }

func (source *blockingPacketSource) LinkType() layers.LinkType { return layers.LinkTypeEthernet }

func (source *blockingPacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	source.readingOn.Do(func() { close(source.reading) })

	select {
	case <-source.done:
		return nil, gopacket.CaptureInfo{}, io.EOF
	case data := <-source.packets:
		return data, gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}, nil
	}
}

// close is what the owner of a capture handle does to end a scan, and the only thing that wakes a
// blocked read.
func (source *blockingPacketSource) close() {
	source.once.Do(func() {
		source.closed.Store(true)
		close(source.done)
	})
}

// TestScanReturnsWithAReaderParkedInABlockingRead is the shutdown path of every real SYN scan.
//
// The reader is parked in a read that only a close will wake. Scan cancels its context and then has
// to finish, because the caller cannot close the sources until Scan has returned -- ScanNetworks
// closes them in a defer that runs afterwards. A Scan that waited for such a reader would wait for
// something only its own return can cause.
func TestScanReturnsWithAReaderParkedInABlockingRead(t *testing.T) {
	t.Parallel()

	source := newBlockingPacketSource()
	t.Cleanup(source.close)

	listenHandler := &listener_handler.ListenHandler{
		ListenPort:        testListenPort,
		TcpIpv4Connection: &fakePacketConn{},
		TcpIpv6Connection: &fakePacketConn{},
	}

	scanner, err := NewScanner(
		listenHandler,
		[]PacketSource{source},
		func(*Result) {},
		port_scanner_config.WithConcurrency(4),
		port_scanner_config.WithTimeout(50*time.Millisecond),
		port_scanner_config.WithSendRetryWait(time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	scanner.resolveSourceIp = fixedSourceIp(testSourceIp)

	_, network, err := net.ParseCIDR("192.0.2.1/32")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	// Wait until the reader is genuinely parked, so the test exercises the case it is about.
	go func() {
		<-source.reading
	}()

	finished := make(chan error, 1)
	go func() {
		finished <- scanner.Scan(t.Context(), []*net.IPNet{network}, []int{80})
	}()

	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("Scan did not return with a reader parked in a blocking read: it waits for a " +
			"reader only its own return can free")
	}
}
