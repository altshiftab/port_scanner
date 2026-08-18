// Package errors holds the sentinel errors of the port scanner. Nil and empty values are reported
// with utils_go's nil_error and empty_error types instead.
package errors

import "errors"

var (
	ErrNotPrivileged           = errors.New("not privileged")
	ErrPortOutOfRange          = errors.New("port out of range")
	ErrTooManyAddresses        = errors.New("targets expand past the address cap")
	ErrScanInProgress          = errors.New("scan in progress")
	ErrTooManyTargets          = errors.New("too many targets")
	ErrInvalidNetworkMask      = errors.New("invalid network mask")
	ErrInvalidPort             = errors.New("invalid port")
	ErrUnsupportedNetworkLayer = errors.New("unsupported network layer")
	ErrNoCaptureHandles        = errors.New("no capture handles could be opened")
	ErrInterfaceNotUp          = errors.New("interface is not up or does not exist")
	ErrConcurrencyOutOfRange   = errors.New("concurrency out of range")
	ErrTimeoutOutOfRange       = errors.New("timeout out of range")
	ErrSendAttemptsOutOfRange  = errors.New("send attempts out of range")
	ErrIndexOutsideRange       = errors.New("index outside range")
	ErrProbeMismatch           = errors.New("reply does not match the outstanding probe")
	ErrLocalAddressNotResolved = errors.New("local address could not be resolved")
	ErrNoProbesSent            = errors.New("no probe could be sent")
)
