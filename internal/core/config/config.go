// Package config defines the project/global config domain types and the load/
// validate logic. Pure: filesystem access is behind a Filesystem port. No SDK
// imports.
package config

import (
	"context"
	"errors"
)

// ErrNotFound is returned when the project config file does not exist.
var ErrNotFound = errors.New(
	"no .byreis.yaml found in the current directory or its parents — " +
		"run `byreis init` to configure this project")

// ProjectConfig is the per-project configuration read from .byreis.yaml.
type ProjectConfig struct {
	// RegistryURL is the URL of the admin registry repo.
	RegistryURL string `yaml:"registry_url"`
	// ProjectID is the registry-canonical project identifier; it binds this
	// project to its registry entry and to the signed manifest.
	ProjectID string `yaml:"project_id"`
	// SecretsDir is the relative path to the secrets directory (default: "secrets").
	SecretsDir string `yaml:"secrets_dir"`
}

// GlobalConfig is the global byreis configuration.
type GlobalConfig struct {
	// ConfigDir is ~/.config/byreis/ (or $BYREIS_CONFIG).
	ConfigDir string
	// CacheDir is ~/.cache/byreis/.
	CacheDir string
}

// Filesystem is the port for config I/O (injected; no real fs in unit tests).
type Filesystem interface {
	// ReadFile reads the named file and returns its contents.
	ReadFile(ctx context.Context, path string) ([]byte, error)
	// WriteFile writes data to the named file with the given permissions.
	WriteFile(ctx context.Context, path string, data []byte, perm uint32) error
	// FileExists reports whether path exists as a regular file.
	FileExists(ctx context.Context, path string) (bool, error)
}

// Loader loads and validates configuration. All implementations must be pure
// functions of the injected Filesystem.
type Loader interface {
	// LoadProject loads .byreis.yaml from dir or its parents.
	LoadProject(ctx context.Context, startDir string) (ProjectConfig, error)
	// LoadGlobal loads the global config.
	LoadGlobal(ctx context.Context) (GlobalConfig, error)
}
