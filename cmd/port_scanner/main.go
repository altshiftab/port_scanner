// Command port_scanner finds open TCP ports on the given targets with SYN probes and prints them,
// one per line, as they are found. It needs CAP_NET_RAW.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftErrorLogger "github.com/altshiftab/utils_go/pkg/log/error_logger"

	portScannerErrors "github.com/altshiftab/port_scanner/pkg/errors"
	"github.com/altshiftab/port_scanner/pkg/port_scanner"
	"github.com/altshiftab/port_scanner/pkg/port_scanner/port_scanner_config"
)

const (
	defaultTimeout = "1s"
	// maxPort is the largest TCP port number.
	maxPort = 65535
)

// parsePortsSpec parses a port specification: a comma-separated list of ports and inclusive
// ranges, such as "22,80,8000-8100". Whitespace around entries is ignored, as are empty entries.
func parsePortsSpec(spec string) ([]int, error) {
	var ports []int

	for entry := range strings.SplitSeq(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		first, last, isRange := strings.Cut(entry, "-")
		start, err := parsePort(first)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("parse port: %w", err), entry)
		}

		end := start
		if isRange {
			end, err = parsePort(last)
			if err != nil {
				return nil, altshiftErrors.New(fmt.Errorf("parse port: %w", err), entry)
			}

			if end < start {
				return nil, altshiftErrors.NewWithTrace(
					fmt.Errorf(
						"%w: %w: range end before start: %s",
						altshiftErrors.ErrParseError, portScannerErrors.ErrInvalidPort, entry,
					),
					entry,
				)
			}
		}

		for port := start; port <= end; port++ {
			ports = append(ports, port)
		}
	}

	if len(ports) == 0 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: no ports in specification", altshiftErrors.ErrParseError),
			spec,
		)
	}

	return ports, nil
}

// parsePort parses one port number and checks that it is one.
func parsePort(text string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		return 0, altshiftErrors.NewWithTrace(fmt.Errorf("%w: strconv atoi: %w", altshiftErrors.ErrParseError, err), text)
	}

	if port < 1 || port > maxPort {
		return 0, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w: %d", altshiftErrors.ErrParseError, portScannerErrors.ErrInvalidPort, port),
			port,
		)
	}

	return port, nil
}

// resultPrinter writes results to its writer, one per line, either as host:port or as JSON.
// Results arrive concurrently, so writes are serialised.
type resultPrinter struct {
	writer io.Writer
	json   bool

	mu sync.Mutex
}

func (printer *resultPrinter) print(result *port_scanner.Result) error {
	if result == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("result"))
	}

	var line string
	if printer.json {
		encoded, err := json.Marshal(result)
		if err != nil {
			return altshiftErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), result)
		}
		line = string(encoded)
	} else {
		line = net.JoinHostPort(result.IpAddress, strconv.Itoa(result.Port))
	}

	printer.mu.Lock()
	defer printer.mu.Unlock()

	if _, err := fmt.Fprintln(printer.writer, line); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("fprintln: %w", err), line)
	}

	return nil
}

func main() {
	logLevel := &slog.LevelVar{}
	logger := altshiftErrorLogger.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger.Logger)

	var targets []string
	var portsSpec string
	var concurrency int
	var timeoutString string
	var includeIpv6 bool
	var interfaceNames []string
	var jsonOutput bool
	var verbose bool

	parser := &argument_parser.Parser{
		Description: "Find open TCP ports with SYN probes. A SYN is sent to every port of every target and " +
			"the SYN/ACKs that come back are reported, one open port per line, as they arrive. " +
			"Needs CAP_NET_RAW.",
		Positionals: []option.Option{
			option.WithNargs(
				option.WithMetavar(
					option.NewStringsOption(0, "", "An IP address or CIDR block to scan.", true, &targets),
					"TARGET",
				),
				option.NargsAtLeastOne,
			),
		},
		Options: []option.Option{
			option.WithMetavar(
				option.NewStringOption(
					'p', "ports",
					"The ports to scan, as a comma-separated list of ports and inclusive ranges, e.g. "+
						"22,80,8000-8100. Defaults to a built-in list of the most commonly open ports.",
					false, &portsSpec,
				),
				"PORTS",
			),
			option.WithDefault(
				option.NewIntOption(
					'n', "concurrency",
					"How many probes may be outstanding at once.",
					false, &concurrency,
				),
				strconv.Itoa(port_scanner_config.DefaultConcurrency),
			),
			option.WithMetavar(
				option.WithDefault(
					option.NewStringOption(
						't', "timeout",
						"How long to wait for the reply to a probe, e.g. 500ms or 2s.",
						false, &timeoutString,
					),
					defaultTimeout,
				),
				"DURATION",
			),
			option.NewBoolOption('6', "ipv6", "Enable IPv6: open an IPv6 raw socket and accept IPv6 targets.", false, &includeIpv6),
			// One name per occurrence, so that a target may follow: a greedy option would swallow it.
			option.WithNargs(
				option.WithMetavar(
					option.NewStringsOption(
						'i', "interface",
						"Capture replies on this interface only. May be repeated. Every interface that is up "+
							"is captured on by default.",
						false, &interfaceNames,
					),
					"NAME",
				),
				option.NargsOne,
			),
			option.NewBoolOption('j', "json", "Print each result as a JSON object instead of host:port.", false, &jsonOutput),
			option.NewBoolOption('v', "verbose", "Log at debug level.", false, &verbose),
		},
	}

	if err := parser.Validate(); err != nil {
		logger.FatalWithExitingMessage(
			"The argument parser is misdeclared.",
			altshiftErrors.New(fmt.Errorf("parser validate: %w", err)),
		)
	}

	parser.ParseOrExit()

	if verbose {
		logLevel.Set(slog.LevelDebug)
	}

	if portsSpec == "" {
		portsSpec = defaultPortsSpec
	}

	ports, err := parsePortsSpec(portsSpec)
	if err != nil {
		logger.FatalWithExitingMessage(
			"The ports could not be parsed.",
			altshiftErrors.New(fmt.Errorf("parse ports spec: %w", err), portsSpec),
		)
	}

	timeout, err := time.ParseDuration(timeoutString)
	if err != nil {
		logger.FatalWithExitingMessage(
			"The timeout could not be parsed.",
			altshiftErrors.New(fmt.Errorf("time parse duration: %w", err), timeoutString),
		)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	printer := &resultPrinter{writer: os.Stdout, json: jsonOutput}

	err = port_scanner.Scan(
		ctx,
		targets,
		ports,
		func(result *port_scanner.Result) {
			if err := printer.print(result); err != nil {
				logger.ErrorWithSkippingMessage(
					"An error occurred when printing a result.",
					altshiftErrors.New(fmt.Errorf("print: %w", err), result),
				)
			}
		},
		port_scanner_config.WithConcurrency(concurrency),
		port_scanner_config.WithTimeout(timeout),
		port_scanner_config.WithSkipIpv6(!includeIpv6),
		port_scanner_config.WithInterfaceNames(interfaceNames...),
	)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			slog.InfoContext(ctx, "The scan was interrupted.")
			os.Exit(130)
		case errors.Is(err, portScannerErrors.ErrNotPrivileged):
			// A user's mistake, not the program's: one line, no stack trace.
			fmt.Fprintln(os.Stderr, "port_scanner: error: sending probes needs CAP_NET_RAW; run as root or grant the "+
				"capability to the binary (setcap cap_net_raw+ep)")
			os.Exit(1)
		case errors.Is(err, altshiftErrors.ErrValidationError), errors.Is(err, altshiftErrors.ErrParseError):
			fmt.Fprintf(os.Stderr, "port_scanner: error: %s\n", err)
			os.Exit(1)
		}

		logger.FatalWithExitingMessage(
			"An error occurred when scanning.",
			altshiftErrors.New(fmt.Errorf("scan: %w", err), targets, concurrency, timeout, includeIpv6, interfaceNames),
		)
	}
}
