// Package writesigner adapts the existing manifestsigner.TextSigner to the
// registry.RegistryWriteSigner port (SignText over a canonical commit message
// body). No new key path. No second keychain slot. No new ed25519 import in
// production code.
//
// Domain separation: the fixed ASCII label "byreis-registry-write/v1\n" is
// applied inside this adapter, before delegating to the TextSigner, so every
// caller inherits it automatically. This is a signature-confusion defence
// between manifest signing and counter-commit signing.
package writesigner

import (
	"context"
	"errors"
	"fmt"

	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
)

// domainSepPrefix is the fixed domain-separation label prepended to every
// counter-commit body before signing. No manifest.Encode output can begin with
// this prefix (manifest format versions match ^byreis\.native\.v[0-9]+$; this
// label uses "/" which is not in that alphabet).
const domainSepPrefix = "byreis-registry-write/v1\n"

// TextSigner is the narrow interface the SignerAdapter requires from the inner
// signer. The production implementation is the *manifestsigner.signer struct,
// which already enforces key-length validation, zeroization, and attested-id
// resolution. No ed25519 import is needed here.
type TextSigner interface {
	SignText(ctx context.Context, text []byte) (signerID string, sig []byte, err error)
}

// SignerAdapter adapts a TextSigner to the registry.RegistryWriteSigner port.
// It prepends the fixed domain-separation prefix before delegating to the inner
// signer so all callers inherit domain separation without any per-call change.
type SignerAdapter struct {
	inner TextSigner
}

// New constructs a SignerAdapter wrapping ms. Returns a non-nil error if ms is nil.
func New(ms TextSigner) (*SignerAdapter, error) {
	if ms == nil {
		return nil, errors.New(
			"writesigner.New: TextSigner must not be nil — " +
				"pass the constructed manifestsigner adapter")
	}
	return &SignerAdapter{inner: ms}, nil
}

// Compile-time assertion: SignerAdapter satisfies the RegistryWriteSigner port.
var _ registryadapter.RegistryWriteSigner = (*SignerAdapter)(nil)

// SignText prepends the domain-separation prefix then delegates to the inner
// TextSigner. The returned signerID and sig come verbatim from the inner
// signer (which enforces attested-id resolution and key-length validation).
func (a *SignerAdapter) SignText(ctx context.Context, text []byte) (signerID string, sig []byte, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", nil, fmt.Errorf("writesigner: SignText cancelled: %w", ctxErr)
	}

	// Apply domain separation: prepend the fixed label so manifest signatures
	// and counter-commit signatures can never be confused.
	separated := make([]byte, 0, len(domainSepPrefix)+len(text))
	separated = append(separated, []byte(domainSepPrefix)...)
	separated = append(separated, text...)

	signerID, sig, err = a.inner.SignText(ctx, separated)
	if err != nil {
		return "", nil, fmt.Errorf("writesigner: signing counter-commit body: %w", err)
	}
	return signerID, sig, nil
}
