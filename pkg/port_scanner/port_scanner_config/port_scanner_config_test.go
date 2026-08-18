package port_scanner_config

import (
	"reflect"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		options []Option
		want    *Config
	}{
		{
			name: "defaults",
			want: &Config{
				Concurrency:    DefaultConcurrency,
				Timeout:        DefaultTimeout,
				SendAttempts:   DefaultSendAttempts,
				SendRetryWait:  DefaultSendRetryWait,
				ConnectTimeout: DefaultConnectTimeout,
			},
		},
		{
			name:    "nil option is skipped",
			options: []Option{nil},
			want: &Config{
				Concurrency:    DefaultConcurrency,
				Timeout:        DefaultTimeout,
				SendAttempts:   DefaultSendAttempts,
				SendRetryWait:  DefaultSendRetryWait,
				ConnectTimeout: DefaultConnectTimeout,
			},
		},
		{
			name: "all options",
			options: []Option{
				WithConcurrency(7),
				WithTimeout(3 * time.Second),
				WithSendAttempts(1),
				WithSendRetryWait(time.Millisecond),
				WithSkipIpv6(true),
				WithInterfaceNames("eth0"),
				WithInterfaceNames("wlan0", "wg0"),
			},
			want: &Config{
				Concurrency:    7,
				Timeout:        3 * time.Second,
				SendAttempts:   1,
				SendRetryWait:  time.Millisecond,
				SkipIpv6:       true,
				InterfaceNames: []string{"eth0", "wlan0", "wg0"},
				ConnectTimeout: DefaultConnectTimeout,
			},
		},
		{
			name:    "later option wins",
			options: []Option{WithConcurrency(1), WithConcurrency(2)},
			want: &Config{
				Concurrency:    2,
				Timeout:        DefaultTimeout,
				SendAttempts:   DefaultSendAttempts,
				SendRetryWait:  DefaultSendRetryWait,
				ConnectTimeout: DefaultConnectTimeout,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := New(testCase.options...); !reflect.DeepEqual(got, testCase.want) {
				t.Errorf("New() = %+v, want %+v", got, testCase.want)
			}
		})
	}
}
