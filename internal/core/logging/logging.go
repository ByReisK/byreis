// Package logging defines the structured-log sink seam used throughout core.
// Adapters outside core provide concrete implementations (e.g. zerolog).
// Core never imports a logging SDK — it receives a Logger at construction time.
//
// The seam exists from the start so the ship-gate suite can assert that no
// secret material ever appears in log output.
package logging

import "context"

// Level is the log severity.
type Level int

// Level values enumerate log severity from least to most severe.
const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Logger is the narrow structured-log port accepted by all core constructors.
// Implementations must never log secret or key material (enforced by the
// ship-gate behavioral suite). Context is carried so logger middleware can
// attach trace IDs.
type Logger interface {
	// Log emits a structured entry. msg is the human-readable summary; fields
	// is an even-length sequence of alternating key/value pairs (all strings).
	// Panics if len(fields) is odd.
	Log(ctx context.Context, level Level, msg string, fields ...string)
}

// Discard is a no-op Logger suitable for tests that do not need log output.
var Discard Logger = discardLogger{}

type discardLogger struct{}

func (discardLogger) Log(_ context.Context, _ Level, _ string, _ ...string) {}
