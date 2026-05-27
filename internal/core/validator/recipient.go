package validator

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsupportedRecipient is returned when a recipient string is malformed or
// names a backend that is not in the closed admit-set. It is the single
// rejection sentinel for recipient classification; callers wrap it with an
// actionable hint and a `byreis doctor` pointer.
var ErrUnsupportedRecipient = errors.New(
	"unsupported age recipient: not a member of the supported recipient backends")

// SupportedRecipientBackends is the closed set of age recipient encodings byreis
// will admit into a recipient set. The map key is the backend discriminator: the
// bech32 HRP after the literal "age1" separator. The empty string denotes a
// native X25519 recipient (HRP "age"); the non-empty keys are age-plugin names.
//
// This is the single authoritative admit-list. It is consumed by registry
// admission (rejecting any recipient whose discriminator is absent here) and by
// the cross-backend fingerprint distinctness vector. It lives in core validator,
// not in registry config or policy.yaml, because admitting a new backend is a
// security closed-world decision that must pull a code change and a crypto/threat
// re-review — it is not deployment policy a registry operator may widen.
//
// Certification status (yubikey is the certified backend; tpm/se/fido2 are
// admitted by format) is a docs/UX distinction, never an admission distinction:
// all five entries are admitted identically here.
var SupportedRecipientBackends = map[string]bool{
	"":        true, // native X25519 (HRP "age")
	"yubikey": true,
	"tpm":     true,
	"se":      true,
	"fido2":   true,
}

// ClassifyRecipient decodes the bech32 human-readable part of an age recipient
// string and returns its backend discriminator: the empty string for a native
// X25519 recipient (HRP "age"), or the lowercase plugin name for a plugin
// recipient (HRP "age1<name>"). It returns a wrapped ErrUnsupportedRecipient,
// carrying an actionable hint, when the string is malformed or names a backend
// outside SupportedRecipientBackends.
//
// Classification decodes the HRP directly and validates the bech32 checksum, so
// a malformed string (bad checksum, illegal character, mixed case) fails closed.
// It deliberately does NOT route through the age plugin parser: a bare X25519
// "age1…" string is reported by that parser as an error ("not a plugin
// recipient"), not as an empty-name result, so classifying on that error would
// mis-route every native recipient. This function performs no network call and
// touches no key material.
func ClassifyRecipient(agePubKey string) (backend string, err error) {
	hrp, decErr := decodeBech32HRP(agePubKey)
	if decErr != nil {
		return "", fmt.Errorf(
			"%w: recipient is not a well-formed age key (%v) — "+
				"check the admins.yaml entry and run `byreis doctor`",
			ErrUnsupportedRecipient, decErr)
	}

	switch {
	case hrp == "age":
		// Native X25519 recipient: empty discriminator.
		backend = ""
	case strings.HasPrefix(hrp, "age1"):
		// Plugin recipient: discriminator is the HRP after the "age1" prefix.
		backend = strings.TrimPrefix(hrp, "age1")
	default:
		return "", fmt.Errorf(
			"%w: recipient has human-readable part %q, which is neither a native "+
				"age key nor an age-plugin recipient — run `byreis doctor`",
			ErrUnsupportedRecipient, hrp)
	}

	if !SupportedRecipientBackends[backend] {
		return "", fmt.Errorf(
			"%w: recipient names plugin backend %q, which byreis does not admit — "+
				"supported backends are yubikey, tpm, se, fido2 (and native age keys); "+
				"run `byreis doctor`",
			ErrUnsupportedRecipient, backend)
	}
	return backend, nil
}

// bech32Charset is the BIP173 data-part charset.
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32Generator are the BIP173 checksum generator polynomials.
var bech32Generator = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

// decodeBech32HRP extracts and validates the human-readable part of a bech32
// string, returning the (lowercase) HRP. It validates the full structure and
// checksum so that a corrupt or non-bech32 string is rejected rather than
// silently yielding a plausible HRP. This is a self-contained BIP173 reader
// scoped to HRP extraction; it does not decode the data payload (byreis never
// interprets the recipient payload — only its backend discriminator matters
// for admission). The age library's own bech32 decoder is internal and not
// importable, so the algorithm is reimplemented here against the same fixed
// constants.
func decodeBech32HRP(s string) (string, error) {
	if s == "" {
		return "", errors.New("empty string")
	}
	// Bech32 is case-insensitive but must not be mixed case.
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", errors.New("mixed-case string")
	}
	lower := strings.ToLower(s)

	// The HRP is everything before the last "1" separator; the data part
	// (incl. the 6-symbol checksum) follows it.
	pos := strings.LastIndex(lower, "1")
	if pos < 1 || pos+7 > len(lower) {
		return "", fmt.Errorf("separator '1' at invalid position %d (len %d)", pos, len(lower))
	}
	hrp := lower[:pos]
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", fmt.Errorf("invalid HRP character at index %d", i)
		}
	}

	data := make([]byte, 0, len(lower)-pos-1)
	for _, c := range lower[pos+1:] {
		idx := strings.IndexRune(bech32Charset, c)
		// IndexRune returns either -1 (not in the 32-char charset) or an index
		// in [0, 31], so the converted value always fits in a byte.
		if idx < 0 || idx >= len(bech32Charset) {
			return "", errors.New("invalid data character")
		}
		data = append(data, byte(idx))
	}
	if !bech32VerifyChecksum(hrp, data) {
		return "", errors.New("invalid checksum")
	}
	return hrp, nil
}

// bech32HRPExpand expands the HRP per BIP173 for the checksum computation.
func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

// bech32Polymod computes the BIP173 checksum polynomial.
func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= bech32Generator[i]
			}
		}
	}
	return chk
}

// bech32VerifyChecksum reports whether data carries a valid bech32 checksum for
// hrp.
func bech32VerifyChecksum(hrp string, data []byte) bool {
	return bech32Polymod(append(bech32HRPExpand(hrp), data...)) == 1
}
