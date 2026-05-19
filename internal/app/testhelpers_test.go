package app_test

import (
	"context"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// ---------------------------------------------------------------------------
// Stub implementations of the narrow ports used by BuildReadPathDeps tests.
// These are defined once here and shared by all *_test.go files in this package.
// ---------------------------------------------------------------------------

// stubArtifactCodec satisfies usecase.ArtifactCodec without any real YAML parsing.
type stubArtifactCodec struct{}

func (s *stubArtifactCodec) DecodeSigned([]byte) (artifact.Signed, error) {
	return artifact.Signed{}, nil
}

func (s *stubArtifactCodec) DecodeUnsigned([]byte) (artifact.Unsigned, error) {
	return artifact.Unsigned{}, nil
}

func (s *stubArtifactCodec) EncodeSigned(artifact.Signed) ([]byte, error) {
	return nil, nil
}

// stubDecryptor satisfies decrypt.Decryptor without any real age crypto.
type stubDecryptor struct{}

func (s *stubDecryptor) Decrypt(_ context.Context, _ artifact.Signed, _ identity.Identity) (map[string]string, error) {
	return nil, nil
}

func (s *stubDecryptor) RoundTripAll(_ context.Context, _ artifact.Signed, _ []identity.Identity) error {
	return nil
}

// Compile-time assertion.
var _ decrypt.Decryptor = (*stubDecryptor)(nil)

// stubIdentityLoader satisfies identity.Loader without any real keychain access.
type stubIdentityLoader struct{}

func (s *stubIdentityLoader) Load(_ context.Context) (identity.Identity, error) {
	return nil, nil
}

// stubVerifier satisfies verify.VerifierOfRecord without any real crypto.
type stubVerifier struct{}

func (s *stubVerifier) VerifyOfRecord(_ context.Context, _ verify.OfRecordInput) error {
	return nil
}

// Compile-time assertion.
var _ verify.VerifierOfRecord = (*stubVerifier)(nil)

// stubRecipientSource satisfies usecase.RecipientSource.
type stubRecipientSource struct{}

func (s *stubRecipientSource) ExpectedRecipients(_ context.Context, _ string) (usecase.VerifiedRecipients, error) {
	return usecase.VerifiedRecipients{}, nil
}

// stubCounterStore satisfies usecase.CounterStore without real registry access.
type stubCounterStore struct{}

func (s *stubCounterStore) CounterAuthority(_ context.Context, _, _ string) (countertypes.CounterAuthority, error) {
	return countertypes.CounterAuthority{}, nil
}

func (s *stubCounterStore) RecordPendingBump(_ context.Context, _ usecase.PendingBumpInput) error {
	return nil
}

func (s *stubCounterStore) CommitBump(_ context.Context, _ usecase.CommitBumpInput) error {
	return nil
}

// stubModeGate satisfies usecase.ModeGate — always allows.
type stubModeGate struct{ deny bool }

func (s *stubModeGate) Allow(_ mode.Command) error {
	if s.deny {
		return mode.ErrPermissionDenied
	}
	return nil
}

// stubFileOfRecordSource satisfies usecase.FileOfRecordSource.
type stubFileOfRecordSource struct{}

func (s *stubFileOfRecordSource) FileOfRecord(_ context.Context, _, _ string) (usecase.FileOfRecord, error) {
	return usecase.FileOfRecord{}, nil
}

// stubEncryptorPort satisfies encrypt.Encryptor (public-key only, never private-key).
type stubEncryptorPort struct{ err error }

func (s *stubEncryptorPort) Encrypt(_ context.Context, _ encrypt.EncryptInput) (artifact.Unsigned, error) {
	if s.err != nil {
		return artifact.Unsigned{}, s.err
	}
	return artifact.Unsigned{}, nil
}

// Compile-time assertion.
var _ encrypt.Encryptor = (*stubEncryptorPort)(nil)
