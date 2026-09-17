// Package banner_config carries the tunables of a banner grab.
package banner_config

import (
	"time"
)

const (
	// DefaultTimeout is how long a grab waits for a service to say something. It is the dominant
	// cost of a grab: a service that speaks first answers in milliseconds, and one that does not
	// costs the whole of this before anything else is tried.
	DefaultTimeout = 3 * time.Second

	// DefaultSettleTimeout is how long the reads after the first wait. A banner arrives in one
	// segment or a few in quick succession, so once the service has started talking the wait for
	// the rest is short.
	DefaultSettleTimeout = 250 * time.Millisecond

	// DefaultLength is how much of what a service says is kept. A banner is a line or two; the
	// limit is there so that a port streaming an endless response cannot be read forever.
	DefaultLength = 4096

	// DefaultDialTimeout bounds the dial of a grab that opens its own connection.
	DefaultDialTimeout = 3 * time.Second
)

// Config holds the tunables of a banner grab. The zero value is not usable; obtain one from New,
// which applies the defaults before the options.
type Config struct {
	// Timeout is how long a grab waits for the service to speak first.
	Timeout time.Duration

	// SettleTimeout is how long each read after the first waits.
	SettleTimeout time.Duration

	// Length is how many bytes of the banner are kept.
	Length int

	// DialTimeout bounds the dial of a grab that opens its own connection.
	DialTimeout time.Duration

	// Tls says whether a TLS handshake is attempted. On a port that conventionally speaks TLS it
	// is the first thing tried; on any other it is what is tried after the port has said nothing
	// in the clear, which costs a second connection.
	Tls bool

	// Http says whether a port that says nothing of its own accord is sent an HTTP request to make
	// it speak. It is what names a web server, which says nothing until it is asked.
	Http bool

	// ServerName is the name presented in the TLS handshake and sent as the HTTP Host header. A
	// scan addresses hosts by address, and a server behind virtual hosting answers an address
	// differently from a name, so a caller that knows the name should pass it.
	ServerName string
}

type Option func(*Config)

// New returns a Config with the defaults applied, then the options in order.
//
// TLS and HTTP probing are on by default: both name services that a passive read cannot, and the
// two together are what turns "443 is open" into "443 is nginx with a certificate for example.com".
func New(options ...Option) *Config {
	config := &Config{
		Timeout:       DefaultTimeout,
		SettleTimeout: DefaultSettleTimeout,
		Length:        DefaultLength,
		DialTimeout:   DefaultDialTimeout,
		Tls:           true,
		Http:          true,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

// WithTimeout sets how long a grab waits for the service to speak first. Values of zero or less are
// ignored, leaving the default in place.
func WithTimeout(timeout time.Duration) Option {
	return func(config *Config) {
		if timeout > 0 {
			config.Timeout = timeout
		}
	}
}

// WithSettleTimeout sets how long each read after the first waits. Values of zero or less are
// ignored, leaving the default in place.
func WithSettleTimeout(settleTimeout time.Duration) Option {
	return func(config *Config) {
		if settleTimeout > 0 {
			config.SettleTimeout = settleTimeout
		}
	}
}

// WithLength sets how many bytes of the banner are kept. Values of zero or less are ignored,
// leaving the default in place.
func WithLength(length int) Option {
	return func(config *Config) {
		if length > 0 {
			config.Length = length
		}
	}
}

// WithDialTimeout bounds the dial of a grab that opens its own connection. Values of zero or less
// are ignored, leaving the default in place.
func WithDialTimeout(dialTimeout time.Duration) Option {
	return func(config *Config) {
		if dialTimeout > 0 {
			config.DialTimeout = dialTimeout
		}
	}
}

// WithTls sets whether a TLS handshake is attempted.
func WithTls(useTls bool) Option {
	return func(config *Config) {
		config.Tls = useTls
	}
}

// WithHttp sets whether a silent port is sent an HTTP request to make it speak.
func WithHttp(useHttp bool) Option {
	return func(config *Config) {
		config.Http = useHttp
	}
}

// WithServerName sets the name presented in the TLS handshake and sent as the HTTP Host header.
func WithServerName(serverName string) Option {
	return func(config *Config) {
		config.ServerName = serverName
	}
}
