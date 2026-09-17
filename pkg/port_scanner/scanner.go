package port_scanner

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/altshiftab/port_scanner/pkg/banner"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
	"github.com/altshiftab/port_scanner/pkg/port_scanner/port_scanner_config"
	"github.com/altshiftab/port_scanner/pkg/types/listener_handler"
	"github.com/altshiftab/port_scanner/pkg/types/permutation"
)

// PacketSource is where a reader gets captured packets from; *CaptureHandle is one.
//
// A read blocks until a frame arrives or the source is closed, and has no timeout of its own.
// Closing it is therefore the only way to wake a reader waiting on a quiet interface: the blocked
// read returns an error, which the reader treats as the end of the scan rather than a failure.
//
// Because the source belongs to the caller, Scan cannot close it, and so does not wait indefinitely
// for a reader parked in one -- it gives readers a moment and leaves the rest to be freed by the
// caller's close. A reader that outlives its scan reports nothing: it delivers no callback once the
// scan's context is done.
type PacketSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType

	// Closed reports whether the source has been closed, which is how a reader
	// tells an ended scan from a failed capture.
	Closed() bool
}

var _ PacketSource = (*CaptureHandle)(nil)

// probe is an outstanding SYN: the target it went to and how to give its slot back.
type probe struct {
	ip   net.IP
	port int
	// release returns the probe's slot to the pool. It is idempotent: the reply and the timeout
	// both call it, and whichever comes second must be harmless.
	release func()
	// answered is set by the first reply that matches, so that a retransmitted SYN/ACK does not
	// produce a second result.
	answered atomic.Bool
}

// readerShutdownGrace is how long a scan waits for its readers once it has cancelled them.
//
// A reader that can come back does so as soon as its pending read yields, which is immediate; one
// parked in a read that only a close will wake never will, and waiting for it would deadlock. The
// grace is therefore short: it is the allowance for the first kind, not a wait for the second.
const readerShutdownGrace = 100 * time.Millisecond

// Scanner sends TCP SYN probes and matches the SYN/ACKs that come back to them. Each outstanding
// probe holds one of Concurrency slots; the slot number is encoded in the probe's sequence number,
// so a reply's acknowledgement number says which slot it answers, and the slot says which target
// was probed. A slot is held until its reply arrives or its timeout passes.
//
// A Scanner does not own its listen handler or packet sources and closes neither. It runs one scan
// at a time.
type Scanner struct {
	listenHandler *listener_handler.ListenHandler
	packetSources []PacketSource
	callback      func(*Result)
	config        *port_scanner_config.Config
	// resolveSourceIp gives the source address of a probe, which the checksum is computed over.
	resolveSourceIp SourceIpResolver

	// mu is held for the duration of a scan; a Scanner runs one at a time.
	mu sync.Mutex
	// slots holds the outstanding probe of each slot number, and nil while a slot is free: a probe
	// clears its slot when it is released. Slots are read by readers and written by the sender
	// and the releases concurrently.
	slots []atomic.Pointer[probe]
	// sequenceBase is added to a slot number to make a probe's sequence number, so that a scan's
	// sequence numbers are not simply 0..Concurrency.
	sequenceBase uint32
	// callbacks tracks the callback invocations in flight, so that a scan does not return before
	// its last result has been delivered.
	callbacks sync.WaitGroup
}

// NewScanner returns a Scanner that sends from listenHandler, reads replies from packetSources and
// reports each open port to callback. Each result is delivered on a goroutine of its own, so the
// callback runs concurrently with itself and must be safe for that; a slow callback does not hold
// up the readers, but does accumulate goroutines. Scan does not return until every callback has.
// Options that are not given take their defaults.
func NewScanner(
	listenHandler *listener_handler.ListenHandler,
	packetSources []PacketSource,
	callback func(*Result),
	options ...port_scanner_config.Option,
) (*Scanner, error) {
	if listenHandler == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("listen handler"))
	}

	if listenPort := listenHandler.ListenPort; listenPort < 1 || listenPort > maxPort {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w: %d", altshiftErrors.ErrValidationError, portScannerErrors.ErrInvalidPort, listenPort),
			listenPort,
		)
	}

	if callback == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("callback"))
	}

	for i, packetSource := range packetSources {
		if packetSource == nil {
			return nil, altshiftErrors.NewWithTrace(nil_error.New("packet source"), i)
		}
	}

	config := port_scanner_config.New(options...)
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	scanner := &Scanner{
		listenHandler:   listenHandler,
		packetSources:   packetSources,
		callback:        callback,
		config:          config,
		resolveSourceIp: KernelSourceIp,
	}

	return scanner, nil
}

// validateConfig rejects tunables the scan cannot run with.
func validateConfig(config *port_scanner_config.Config) error {
	if config == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("config"))
	}

	if config.Concurrency < 1 || uint64(config.Concurrency) > math.MaxUint32 { //nolint:gosec // Negative values are excluded by the first operand.
		return altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: %w: %d",
				altshiftErrors.ErrValidationError, portScannerErrors.ErrConcurrencyOutOfRange, config.Concurrency,
			),
		)
	}

	if config.Timeout <= 0 {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: %w: %s",
				altshiftErrors.ErrValidationError, portScannerErrors.ErrTimeoutOutOfRange, config.Timeout,
			),
		)
	}

	if config.SendAttempts < 1 {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: %w: %d",
				altshiftErrors.ErrValidationError, portScannerErrors.ErrSendAttemptsOutOfRange, config.SendAttempts,
			),
		)
	}

	if config.SendRetryWait < 0 {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: %w: %s",
				altshiftErrors.ErrValidationError, portScannerErrors.ErrTimeoutOutOfRange, config.SendRetryWait,
			),
		)
	}

	return nil
}

// Scan probes every port of every address in the networks, in a pseudo-random order, and returns
// once every probe has been answered or has timed out. It returns the context's error if the
// context ends first; results reported until then stand.
//
// Every callback has returned by the time Scan does. A reader may not have: one parked in a packet
// source read can only be woken by the caller closing that source, which the caller cannot do until
// this returns, so waiting for it would deadlock. Such a reader delivers nothing further and ends
// as soon as the source is closed.
//
// A probe that cannot be prepared or sent is logged and skipped; the scan fails only if no probe
// at all could be sent. A packet source that fails is logged and dropped; the scan fails only if
// none is left.
func (scanner *Scanner) Scan(ctx context.Context, networks []*net.IPNet, ports []int) error {
	if scanner == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("scanner"))
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context err: %w", err)
	}

	if !scanner.mu.TryLock() {
		return altshiftErrors.NewWithTrace(portScannerErrors.ErrScanInProgress)
	}
	defer scanner.mu.Unlock()

	space, err := newTargetSpace(networks, ports)
	if err != nil {
		return fmt.Errorf("new target space: %w", err)
	}

	if err := scanner.checkAddressFamilies(space); err != nil {
		return fmt.Errorf("check address families: %w", err)
	}

	sequenceBase, shuffleSeed, err := randomValues()
	if err != nil {
		return fmt.Errorf("random values: %w", err)
	}

	concurrency := scanner.config.Concurrency
	scanner.slots = make([]atomic.Pointer[probe], concurrency)
	scanner.sequenceBase = sequenceBase

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// freeSlots is the pool of slot numbers. Every number is in the channel or held by exactly one
	// probe, so a release never blocks.
	freeSlots := make(chan uint32, concurrency)
	for i := range concurrency {
		freeSlots <- uint32(i) //nolint:gosec // concurrency is validated to fit a uint32.
	}

	// The readers stop when scanCtx ends. A reader that fails is logged and dropped; when the last
	// one fails there is nothing left to hear replies with, and the scan ends.
	readerErrors := make(chan error, len(scanner.packetSources))
	var liveReaders atomic.Int64
	liveReaders.Store(int64(len(scanner.packetSources)))
	var readers sync.WaitGroup
	for _, packetSource := range scanner.packetSources {
		readers.Go(func() {
			err := scanner.readReplies(scanCtx, packetSource)
			if err == nil {
				return
			}

			readerErrors <- err
			if liveReaders.Add(-1) == 0 {
				cancel()
				return
			}

			slog.WarnContext(
				altshiftContext.WithError(scanCtx, fmt.Errorf("read replies: %w", err)),
				"A packet source failed. Continuing without it.",
			)
		})
	}

	sendErr := scanner.sendProbes(scanCtx, space, shuffleSeed, freeSlots)

	// Give the replies to the last probes the same chance the earlier ones had.
	if sendErr == nil && scanCtx.Err() == nil {
		select {
		case <-time.After(scanner.config.Timeout):
		case <-scanCtx.Done():
		}
	}

	cancel()

	// A reader parked in a packet source read cannot be woken by the cancellation above. A capture
	// handle has no read deadline: the read returns when a frame arrives or when the handle is
	// closed, and on a quiet interface -- which is most of them, behind a filter this narrow --
	// neither happens. Closing it is the caller's to do, since a Scanner does not own its sources,
	// and the caller cannot do it until this returns. Waiting for such a reader here is therefore
	// waiting for something only this return can bring about.
	//
	// So readers are given a moment and then left. A reader that can return does so as soon as its
	// read yields, which is immediate; one that cannot is freed by the caller's close a moment
	// later. Nothing is lost by not waiting for it: it dispatches no callback once the context is
	// done, and readerErrors holds one slot per source, so a late failure can neither block nor be
	// reported into a closed channel.
	waitFor(&readers, readerShutdownGrace)

	// Readers dispatch no callbacks once the context is done, so every callback that will ever be
	// started has been; this waits for the last of them.
	scanner.callbacks.Wait()

	var errs []error
	if sendErr != nil {
		errs = append(errs, fmt.Errorf("send probes: %w", sendErr))
	}
	// Reader errors have been logged as they happened; they fail the scan only if every reader
	// failed, since the ones that failed early were still counted on for replies.
	//
	// Drained rather than ranged over: the channel is never closed, because a reader that outlived
	// the wait above may still report a failure into it.
	if len(scanner.packetSources) != 0 && liveReaders.Load() == 0 {
		for len(readerErrors) > 0 {
			errs = append(errs, fmt.Errorf("read replies: %w", <-readerErrors))
		}
	}
	if err := ctx.Err(); err != nil {
		errs = append(errs, fmt.Errorf("context err: %w", err))
	}

	return errors.Join(errs...)
}

// randomValues draws the per-scan sequence number base and shuffle seed. Neither is a secret, but
// a scan should not be trivially recognisable by its sequence numbers, nor visit targets in the
// same order every time.
func randomValues() (uint32, uint64, error) {
	var buffer [12]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return 0, 0, altshiftErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	return binary.LittleEndian.Uint32(buffer[:4]), binary.LittleEndian.Uint64(buffer[4:]), nil
}

// checkAddressFamilies rejects targets of a family the listen handler has no raw socket for, so that
// the mismatch is reported once and up front rather than once per probe.
func (scanner *Scanner) checkAddressFamilies(space *targetSpace) error {
	for _, network := range space.networks {
		if _, err := scanner.listenHandler.Connection(network.IP); err != nil {
			return altshiftErrors.New(
				fmt.Errorf("%w: listen handler connection: %w", altshiftErrors.ErrValidationError, err),
				network,
			)
		}
	}

	return nil
}

// sendProbes walks the target space in shuffled order, preparing and sending a probe for each
// target. A target whose probe cannot be prepared or sent is logged and skipped. It returns when
// the space is exhausted or the context ends, and with an error if not a single probe went out.
func (scanner *Scanner) sendProbes(
	ctx context.Context,
	space *targetSpace,
	shuffleSeed uint64,
	freeSlots chan uint32,
) error {
	size := space.Size()
	shuffle := permutation.New(size, shuffleSeed)
	sourceIps := newCachedSourceIpResolver(scanner.resolveSourceIp)
	buffer := gopacket.NewSerializeBuffer()
	timeout := scanner.config.Timeout
	listenPort := scanner.listenHandler.ListenPort

	// A source address failure is logged once per network, since it applies to the network's
	// remaining targets just the same and they are many.
	unresolvableNetworks := make([]bool, len(space.networks))

	var sent uint64
	var lastErr error

	for i := range size {
		if ctx.Err() != nil {
			return nil
		}

		targetIndex := shuffle.Index(i)
		destinationIp, destinationPort, networkIndex, err := space.Target(targetIndex)
		if err != nil {
			return altshiftErrors.New(fmt.Errorf("target: %w", err), targetIndex)
		}

		sourceIp, err := sourceIps.Resolve(destinationIp)
		if err != nil {
			lastErr = altshiftErrors.New(fmt.Errorf("resolve source ip: %w", err), destinationIp)
			if !unresolvableNetworks[networkIndex] {
				unresolvableNetworks[networkIndex] = true
				slog.WarnContext(
					altshiftContext.WithError(ctx, lastErr),
					"No source address could be resolved for a target. Skipping it and, silently, "+
						"the rest of its network's targets that fail the same way.",
				)
			}
			continue
		}

		networkLayer, err := NewProbeNetworkLayer(sourceIp, destinationIp)
		if err != nil {
			return altshiftErrors.New(fmt.Errorf("new probe network layer: %w", err), sourceIp, destinationIp)
		}

		connection, err := scanner.listenHandler.Connection(destinationIp)
		if err != nil {
			return altshiftErrors.New(fmt.Errorf("listen handler connection: %w", err), destinationIp)
		}

		var slot uint32
		select {
		case <-ctx.Done():
			return nil
		case slot = <-freeSlots:
		}

		outstanding := &probe{ip: destinationIp, port: destinationPort}
		outstanding.release = sync.OnceFunc(func() {
			// The slot is cleared before it is handed back, so that a probe never sees an
			// earlier probe in the slot it was just given.
			scanner.slots[slot].CompareAndSwap(outstanding, nil)
			freeSlots <- slot
		})
		scanner.slots[slot].Store(outstanding)

		tcpLayer, err := NewProbeTcpLayer(listenPort, destinationPort, scanner.sequenceBase+slot)
		if err != nil {
			outstanding.release()
			return altshiftErrors.New(fmt.Errorf("new probe tcp layer: %w", err), destinationPort)
		}

		if err := scanner.sendWithRetries(ctx, tcpLayer, networkLayer, connection, buffer); err != nil {
			lastErr = altshiftErrors.New(
				fmt.Errorf("send with retries: %w", err),
				destinationIp, destinationPort,
			)
			slog.WarnContext(
				altshiftContext.WithError(ctx, lastErr),
				"A probe could not be sent. Skipping its target.",
			)
			outstanding.release()
			continue
		}

		sent++
		time.AfterFunc(timeout, outstanding.release)
	}

	if sent == 0 && size != 0 && ctx.Err() == nil {
		return altshiftErrors.New(fmt.Errorf("%w: %w", portScannerErrors.ErrNoProbesSent, lastErr))
	}

	return nil
}

// isTransientSendError reports whether a send failure may well succeed if simply tried again: the
// socket buffer being full or the call being interrupted. Anything else (no route, a firewall
// refusing the packet) will fail the same way every time.
func isTransientSendError(err error) bool {
	return errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR)
}

// sendWithRetries sends a probe, trying again after a pause when sending fails for a transient
// reason. It returns the last error when the probe could not be sent.
func (scanner *Scanner) sendWithRetries(
	ctx context.Context,
	tcpLayer *layers.TCP,
	networkLayer gopacket.NetworkLayer,
	connection net.PacketConn,
	buffer gopacket.SerializeBuffer,
) error {
	attempts := scanner.config.SendAttempts
	for attempt := 1; ; attempt++ {
		err := SendTcpPacket(tcpLayer, networkLayer, connection, buffer)
		if err == nil {
			return nil
		}

		if attempt >= attempts || !isTransientSendError(err) {
			return altshiftErrors.New(fmt.Errorf("send tcp packet: %w", err), attempt)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("context err: %w", ctx.Err())
		case <-time.After(scanner.config.SendRetryWait):
		}
	}
}

// readReplies reads packets from the source until the context ends or the source is exhausted,
// matching each SYN/ACK to its probe. It returns an error only when the source fails.
func (scanner *Scanner) readReplies(ctx context.Context, packetSource PacketSource) error {
	if packetSource == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("packet source"))
	}

	decoder := newReplyDecoder(packetSource.LinkType())

	for ctx.Err() == nil {
		data, _, err := packetSource.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			// A read returns only when a frame arrives or the source is
			// closed, and closing it is how the scan is ended - so an error
			// from a closed source is the expected way out, not a failure.
			if packetSource.Closed() {
				return nil
			}

			return altshiftErrors.NewWithTrace(fmt.Errorf("read packet data: %w", err))
		}

		if reply, ok := decoder.decode(data); ok {
			// Checked again here rather than only at the top of the loop: the scan may have ended
			// while this frame was being waited for, and a reader that has outlived its scan must
			// not deliver a result to a caller that has already been told the scan is over.
			if ctx.Err() != nil {
				return nil
			}

			scanner.consumeReply(ctx, reply)
		}
	}

	return nil
}

// waitFor waits for the group to finish, giving up after the grace period.
//
// It exists for one situation: a goroutine blocked on something only the caller of this package can
// unblock. Waiting without a bound would deadlock, and not waiting at all would give up on the
// goroutines that were about to finish anyway.
func waitFor(group *sync.WaitGroup, grace time.Duration) {
	finished := make(chan struct{})

	go func() {
		group.Wait()
		close(finished)
	}()

	timer := time.NewTimer(grace)
	defer timer.Stop()

	select {
	case <-finished:
	case <-timer.C:
	}
}

// consumeReply matches a SYN/ACK to the probe in the slot its acknowledgement number names and, if
// it is the probe's first answer, releases the slot and reports the open port.
func (scanner *Scanner) consumeReply(ctx context.Context, reply *reply) {
	if reply == nil {
		return
	}

	// The reply acknowledges the probe's sequence number plus one.
	slot := reply.ackNumber - 1 - scanner.sequenceBase
	if uint64(slot) >= uint64(len(scanner.slots)) {
		scanner.debug(ctx, "A reply acknowledges a sequence number that names no slot. Skipping.", func() error {
			return altshiftErrors.NewWithTrace(portScannerErrors.ErrIndexOutsideRange, slot, reply)
		})
		return
	}

	outstanding := scanner.slots[slot].Load()
	if outstanding == nil {
		return
	}

	if reply.sourcePort != outstanding.port || !reply.sourceIp.Equal(outstanding.ip) {
		// A late reply to an earlier probe whose slot has since been reused, or an unrelated
		// segment; either way, not what the slot is waiting for.
		scanner.debug(ctx, "A reply does not match the probe in its slot. Skipping.", func() error {
			return altshiftErrors.NewWithTrace(
				portScannerErrors.ErrProbeMismatch,
				reply.sourceIp.String(), reply.sourcePort, outstanding.ip.String(), outstanding.port,
			)
		})
		return
	}

	if !outstanding.answered.CompareAndSwap(false, true) {
		return
	}

	outstanding.release()

	result := &Result{
		IpAddress: reply.sourceIp.String(),
		Port:      reply.sourcePort,
		Transport: TransportTcp,
		IpVersion: reply.ipVersion,
	}
	// The callback is the caller's and may be slow; it must not hold up the reader, which has the
	// capture buffer behind it.
	scanner.callbacks.Go(func() {
		// A SYN scan never completed a handshake, so there is no connection to read a banner from
		// and one has to be opened. It happens here rather than in the reader for the same reason
		// the callback does: it is seconds of waiting, and the capture buffer is filling behind it.
		if scanner.config.Banner {
			result.Banner = banner.GrabAddress(
				ctx,
				result.IpAddress,
				result.Port,
				scanner.config.BannerOptions...,
			)
		}

		scanner.callback(result)
	})
}

// debug logs at debug level with an error built only if that level is enabled: unmatched packets
// are common and their errors carry stack traces, which are not worth capturing unseen.
func (scanner *Scanner) debug(ctx context.Context, message string, makeErr func() error) {
	logger := slog.Default()
	if !logger.Enabled(ctx, slog.LevelDebug) {
		return
	}

	logger.DebugContext(altshiftContext.WithError(ctx, makeErr()), message)
}
