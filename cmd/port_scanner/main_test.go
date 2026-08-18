package main

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"

	"github.com/altshiftab/port_scanner/pkg/port_scanner"
)

func TestParsePortsSpec(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{name: "single", spec: "80", want: []int{80}},
		{name: "list", spec: "22,80,443", want: []int{22, 80, 443}},
		{name: "range", spec: "8000-8003", want: []int{8000, 8001, 8002, 8003}},
		{name: "single-element range", spec: "80-80", want: []int{80}},
		{name: "mixed with whitespace and empty entries", spec: " 22, 80-82,,443 ,\n8080\n", want: []int{22, 80, 81, 82, 443, 8080}},
		{name: "duplicates are kept for the scanner to fold", spec: "80,80", want: []int{80, 80}},
		{name: "extremes", spec: "1,65535", want: []int{1, 65535}},
		{name: "empty", spec: "", wantErr: true},
		{name: "only separators", spec: ",,", wantErr: true},
		{name: "zero", spec: "0", wantErr: true},
		{name: "too large", spec: "65536", wantErr: true},
		{name: "negative", spec: "-1", wantErr: true},
		{name: "not a number", spec: "http", wantErr: true},
		{name: "reversed range", spec: "90-80", wantErr: true},
		{name: "open range", spec: "80-", wantErr: true},
		{name: "range with a bad end", spec: "80-x", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := parsePortsSpec(testCase.spec)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("parsePortsSpec(%q) = %v, want an error", testCase.spec, got)
				}
				if !errors.Is(err, altshiftErrors.ErrParseError) {
					t.Fatalf("parsePortsSpec(%q) error = %v, want a parse error", testCase.spec, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("parsePortsSpec(%q) error = %v", testCase.spec, err)
			}
			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("parsePortsSpec(%q) = %v, want %v", testCase.spec, got, testCase.want)
			}
		})
	}
}

func TestDefaultPortsSpecParses(t *testing.T) {
	t.Parallel()

	ports, err := parsePortsSpec(defaultPortsSpec)
	if err != nil {
		t.Fatalf("parsePortsSpec(defaultPortsSpec) error = %v", err)
	}

	if len(ports) < 3000 {
		t.Fatalf("the default port list has %d ports; it is meant to be the long list of common ports", len(ports))
	}
	for _, port := range ports {
		if port < 1 || port > maxPort {
			t.Fatalf("the default port list contains %d", port)
		}
	}
}

func TestResultPrinter(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		json    bool
		result  *port_scanner.Result
		want    string
		wantErr bool
	}{
		{
			name:   "ipv4 plain",
			result: &port_scanner.Result{IpAddress: "192.0.2.1", Port: 80, Transport: "tcp", IpVersion: 4},
			want:   "192.0.2.1:80\n",
		},
		{
			name:   "ipv6 plain is bracketed",
			result: &port_scanner.Result{IpAddress: "2001:db8::1", Port: 443, Transport: "tcp", IpVersion: 6},
			want:   "[2001:db8::1]:443\n",
		},
		{
			name:   "json",
			json:   true,
			result: &port_scanner.Result{IpAddress: "192.0.2.1", Port: 80, Transport: "tcp", IpVersion: 4},
			want:   `{"ip_address":"192.0.2.1","port":80,"transport":"tcp","ip_version":4}` + "\n",
		},
		{name: "nil result", result: nil, wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var buffer bytes.Buffer
			printer := &resultPrinter{writer: &buffer, json: testCase.json}

			err := printer.print(testCase.result)
			if testCase.wantErr {
				if _, ok := errors.AsType[*nil_error.Error](err); !ok {
					t.Fatalf("print() error = %v, want a nil error", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("print() error = %v", err)
			}
			if got := buffer.String(); got != testCase.want {
				t.Fatalf("print() wrote %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestResultPrinterWriteError(t *testing.T) {
	t.Parallel()

	printer := &resultPrinter{writer: &failingWriter{}}
	if err := printer.print(&port_scanner.Result{IpAddress: "192.0.2.1", Port: 80}); err == nil {
		t.Fatalf("print() error = nil, want the write error")
	} else if !strings.Contains(err.Error(), "fprintln") {
		t.Fatalf("print() error = %v, want it to name the write", err)
	}
}

var errWriteFailed = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errWriteFailed
}
