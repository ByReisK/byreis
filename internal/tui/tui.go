// Package tui is the interactive TUI shell for byreis.
//
// This package is a placeholder; the actual bubbletea-based TUI screens
// (submit, admin review, and related flows) are implemented in a later release.
//
// Architecture constraints enforced by depguard and this package's ceiling gate:
//   - bubbletea, lipgloss, and huh are confined to this package tree.
//   - internal/core/** is never imported by this package for UI purposes;
//     the TUI consumes core use-case ports via an injected tui.Deps struct.
//   - Zero new internal/core exported symbols are permitted from TUI work;
//     any addition fails make test-tui-core-ceiling.
package tui
