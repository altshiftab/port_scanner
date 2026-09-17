package banner_config

import (
	"testing"
	"time"
)

func TestNewAppliesDefaults(t *testing.T) {
	t.Parallel()

	config := New()

	testCases := []struct {
		name   string
		got    any
		expect any
	}{
		{name: "timeout", got: config.Timeout, expect: DefaultTimeout},
		{name: "settle timeout", got: config.SettleTimeout, expect: DefaultSettleTimeout},
		{name: "length", got: config.Length, expect: DefaultLength},
		{name: "dial timeout", got: config.DialTimeout, expect: DefaultDialTimeout},
		// Both probes are on by default: each names services a passive read cannot.
		{name: "tls", got: config.Tls, expect: true},
		{name: "http", got: config.Http, expect: true},
		{name: "server name", got: config.ServerName, expect: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if testCase.got != testCase.expect {
				t.Errorf("%s = %v, want %v", testCase.name, testCase.got, testCase.expect)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		option Option
		check  func(*Config) bool
	}{
		{
			name:   "timeout",
			option: WithTimeout(7 * time.Second),
			check:  func(config *Config) bool { return config.Timeout == 7*time.Second },
		},
		{
			name:   "settle timeout",
			option: WithSettleTimeout(11 * time.Millisecond),
			check:  func(config *Config) bool { return config.SettleTimeout == 11*time.Millisecond },
		},
		{
			name:   "length",
			option: WithLength(128),
			check:  func(config *Config) bool { return config.Length == 128 },
		},
		{
			name:   "dial timeout",
			option: WithDialTimeout(5 * time.Second),
			check:  func(config *Config) bool { return config.DialTimeout == 5*time.Second },
		},
		{
			name:   "tls off",
			option: WithTls(false),
			check:  func(config *Config) bool { return !config.Tls },
		},
		{
			name:   "http off",
			option: WithHttp(false),
			check:  func(config *Config) bool { return !config.Http },
		},
		{
			name:   "server name",
			option: WithServerName("example.com"),
			check:  func(config *Config) bool { return config.ServerName == "example.com" },
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if !testCase.check(New(testCase.option)) {
				t.Errorf("%s was not applied", testCase.name)
			}
		})
	}
}

// TestNonPositiveDurationsKeepTheDefault is the property the options are written for: a caller
// passing a zero value it did not set should get the default, not a grab that times out instantly
// and reports every port silent.
func TestNonPositiveDurationsKeepTheDefault(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		config *Config
		got    func(*Config) any
		expect any
	}{
		{
			name:   "zero timeout",
			config: New(WithTimeout(0)),
			got:    func(config *Config) any { return config.Timeout },
			expect: DefaultTimeout,
		},
		{
			name:   "negative timeout",
			config: New(WithTimeout(-time.Second)),
			got:    func(config *Config) any { return config.Timeout },
			expect: DefaultTimeout,
		},
		{
			name:   "zero settle timeout",
			config: New(WithSettleTimeout(0)),
			got:    func(config *Config) any { return config.SettleTimeout },
			expect: DefaultSettleTimeout,
		},
		{
			name:   "zero length",
			config: New(WithLength(0)),
			got:    func(config *Config) any { return config.Length },
			expect: DefaultLength,
		},
		{
			name:   "negative length",
			config: New(WithLength(-1)),
			got:    func(config *Config) any { return config.Length },
			expect: DefaultLength,
		},
		{
			name:   "zero dial timeout",
			config: New(WithDialTimeout(0)),
			got:    func(config *Config) any { return config.DialTimeout },
			expect: DefaultDialTimeout,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := testCase.got(testCase.config); got != testCase.expect {
				t.Errorf("= %v, want the default %v", got, testCase.expect)
			}
		})
	}
}

func TestNewIgnoresNilOptions(t *testing.T) {
	t.Parallel()

	config := New(nil, WithLength(64), nil)

	if config.Length != 64 {
		t.Errorf("Length = %d, want 64", config.Length)
	}
}

// TestOptionsApplyInOrder fixes the rule for a caller that passes the same option twice, which is
// what happens when a default set is appended to by a caller.
func TestOptionsApplyInOrder(t *testing.T) {
	t.Parallel()

	config := New(WithLength(64), WithLength(256))

	if config.Length != 256 {
		t.Errorf("Length = %d, want the last option to win with 256", config.Length)
	}
}
