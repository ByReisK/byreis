// Package artifact defines the on-disk artifact domain types: Unsigned (a
// contributor submission without manifest_sig) and Signed (a file-of-record
// with a mandatory Ed25519 manifest_sig). These are pure domain structs; YAML
// (de)serialization lives here too.
//
// Serialization order is NOT the signing order. The canonical signing bytes are
// produced by internal/core/crypto/manifest, not by this package's marshaller.
package artifact

// FormatVersionPrefix is the required prefix for the format_version field.
// The full value must match ^byreis\.native\.v[0-9]+$.
const FormatVersionPrefix = "byreis.native."

// EncryptedValue is a single-value age ciphertext blob (armored).
type EncryptedValue string

// RecipientEntry is the display copy of a recipient fingerprint in the on-disk
// artifact. It is never trusted as the recipient authority: the authoritative
// recipient set comes only from a signature-verified registry fetch.
type RecipientEntry struct {
	FP string `yaml:"fp"` // 64 lowercase hex chars, full 32-byte sha256 of the recipient key
}

// ManifestSig is the Ed25519 signature block present in a Signed artifact.
type ManifestSig struct {
	Signer string `yaml:"signer"` // admin id
	Sig    string `yaml:"sig"`    // base64-encoded Ed25519 signature
}

// Metadata is the byreis: block embedded in both Unsigned and Signed files.
type Metadata struct {
	FormatVersion string           `yaml:"format_version"`
	ProjectID     string           `yaml:"project_id"` // binds the artifact to its project identity
	File          string           `yaml:"file"`       // logical file name; binds the artifact to its slot
	Counter       uint64           `yaml:"counter"`    // display copy; the registry is the acceptance authority
	Recipients    []RecipientEntry `yaml:"recipients"` // display copy; the verified registry is the authority
}

// Unsigned is a contributor submission artifact. It has no manifest_sig.
// VerifySubmission validates structure only (StateUnverified).
type Unsigned struct {
	Values map[string]EncryptedValue `yaml:",inline"`
	Byreis Metadata                  `yaml:"byreis"`
}

// Signed is a file-of-record: an Unsigned body plus a mandatory ManifestSig
// added by an admin at merge. VerifyOfRecord requires this signature; an absent
// signature is ErrUnsigned — there is no downgrade-to-unsigned path.
type Signed struct {
	Values      map[string]EncryptedValue `yaml:",inline"`
	Byreis      Metadata                  `yaml:"byreis"`
	ManifestSig ManifestSig               `yaml:"manifest_sig"`
}
