// Package port_scanner_config carries the tunables of a scan.
package port_scanner_config

import (
	"time"
)

const (
	// DefaultConcurrency is how many probes may be outstanding at once, and so also the number of
	// distinct sequence numbers a scan cycles through.
	DefaultConcurrency = 500
	// DefaultTimeout is how long a probe waits for its reply before its slot is given up.
	DefaultTimeout = time.Second
	// DefaultSendAttempts is how many times a probe is sent before its target is given up on.
	DefaultSendAttempts = 3
	// DefaultSendRetryWait is the pause between send attempts of the same probe.
	DefaultSendRetryWait = 250 * time.Millisecond
)

// Config holds the tunables of a scan. The zero value is not usable; obtain one from New, which
// applies the defaults before the options.
type Config struct {
	// Concurrency is the number of probes that may be outstanding at once.
	Concurrency int
	// Timeout is how long a probe waits for its reply. It is also how long the scan lingers after
	// the last probe to collect the last replies.
	Timeout time.Duration
	// SendAttempts is how many times a probe is sent when sending fails.
	SendAttempts int
	// SendRetryWait is the pause between send attempts of the same probe.
	SendRetryWait time.Duration
	// SkipIpv6 leaves the IPv6 raw socket unopened, for hosts without IPv6. IPv6 targets are then
	// rejected.
	SkipIpv6 bool
	// InterfaceNames restricts packet capture to the named interfaces. Every interface that is up
	// is captured on when it is empty.
	InterfaceNames []string
}

type Option func(*Config)

// New returns a Config with the defaults applied, then the options in order.
func New(options ...Option) *Config {
	config := &Config{
		Concurrency:   DefaultConcurrency,
		Timeout:       DefaultTimeout,
		SendAttempts:  DefaultSendAttempts,
		SendRetryWait: DefaultSendRetryWait,
	}
	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

// WithConcurrency sets how many probes may be outstanding at once.
func WithConcurrency(concurrency int) Option {
	return func(config *Config) {
		config.Concurrency = concurrency
	}
}

// WithTimeout sets how long a probe waits for its reply.
func WithTimeout(timeout time.Duration) Option {
	return func(config *Config) {
		config.Timeout = timeout
	}
}

// WithSendAttempts sets how many times a probe is sent when sending fails.
func WithSendAttempts(sendAttempts int) Option {
	return func(config *Config) {
		config.SendAttempts = sendAttempts
	}
}

// WithSendRetryWait sets the pause between send attempts of the same probe.
func WithSendRetryWait(sendRetryWait time.Duration) Option {
	return func(config *Config) {
		config.SendRetryWait = sendRetryWait
	}
}

// WithSkipIpv6 leaves the IPv6 raw socket unopened and rejects IPv6 targets.
func WithSkipIpv6(skipIpv6 bool) Option {
	return func(config *Config) {
		config.SkipIpv6 = skipIpv6
	}
}

// WithInterfaceNames restricts packet capture to the named interfaces.
func WithInterfaceNames(interfaceNames ...string) Option {
	return func(config *Config) {
		config.InterfaceNames = append(config.InterfaceNames, interfaceNames...)
	}
}
