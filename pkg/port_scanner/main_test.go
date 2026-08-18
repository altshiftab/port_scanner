package port_scanner

import (
	"log/slog"
	"os"
	"testing"
)

// TestMain silences the default logger: the scanner logs skipped probes and dropped sources, and
// several tests provoke exactly those.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.DiscardHandler))

	os.Exit(m.Run())
}
