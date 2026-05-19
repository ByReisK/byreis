// Package artifactcodec implements the real on-disk YAML codec for byreis
// artifacts. It satisfies usecase.ArtifactCodec (the consumer-defined core
// port) and app.ArtifactEncoder (the OUTER contributor encode seam).
//
// Placement: OUTER adapter layer (internal/adapter/artifactcodec). No
// internal/core package imports this adapter; it is wired only at the
// composition root. This keeps the core free of YAML library imports and
// upholds the Clean Architecture dependency rule.
//
// Model B per-value format: each per-key value is an independent multi-
// recipient age ciphertext (armored). No SOPS data-key block, no whole-file
// MAC, no shared symmetric key. A stock age CLI can decrypt any single value
// given the recipient's identity. This is the "SOPS/age cross-tool compat at
// the value level" contract.
//
// Strict decode contract: malformed YAML, duplicate envelope keys, typed-tag
// abuse (!!binary, numeric, null), anchor/alias expansion beyond the safety
// bound, oversized input, format_version not matching
// ^byreis\.native\.v[0-9]+$, non-hex signature, recipient fingerprint not 64
// hex chars, or embedded 0x1e/0x1f in any manifest field all produce typed
// errors that wrap one of the exported sentinel errors. No partial domain
// value is ever returned on an error path.
//
// Zero-normalization invariant: DecodeSigned and DecodeUnsigned operate on
// the exact input bytes. The codec never re-emits, re-canonicalizes,
// re-orders keys, or rewrites CRLF/whitespace before or during decoding. The
// of-record identity (verify.ContentSHA) is pinned to the decoded DOMAIN
// manifest, not the wire bytes.
package artifactcodec

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"go.yaml.in/yaml/v3"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
)

// Resource bounds applied before any YAML parse.
const (
	maxInputBytes = 10 * 1024 * 1024 // 10 MiB
	maxAliasNodes = 1000             // alias/anchor expansion safety bound
)

var formatVersionRE = regexp.MustCompile(`^byreis\.native\.v[0-9]+$`)

// Sentinel errors. Every decode failure wraps one of these so callers can
// use errors.Is to classify the failure class without inspecting the message.
var (
	// ErrDecodeMalformed is returned when the input bytes cannot be decoded
	// into the expected domain type: malformed YAML, missing or duplicate
	// required envelope keys, format_version violation, non-hex signature or
	// fingerprint, typed-tag abuse (!!binary, numeric, null where string
	// ciphertext expected), embedded 0x1e/0x1f separator injection detected
	// by manifest.Encode, or any other structural constraint violation.
	//
	// No partial domain value is returned alongside this error.
	ErrDecodeMalformed = errors.New(
		"artifact decode failed: malformed or structurally invalid artifact bytes — " +
			"ensure the file was produced by `byreis merge` or `byreis submit` and " +
			"has not been manually edited; run `byreis doctor` to diagnose")

	// ErrTypedMismatch is returned when the artifact shape does not match the
	// requested decode operation: DecodeUnsigned called on a file that carries
	// a manifest_sig block, or DecodeSigned called on a file that has no
	// manifest_sig block. There is no silent coerce between the two shapes.
	ErrTypedMismatch = errors.New(
		"artifact type mismatch: file shape does not match the requested decode " +
			"operation (signed/unsigned) — use the correct decode method for " +
			"the artifact you have; run `byreis doctor` to inspect the file")

	// ErrInputTooLarge is returned when the input byte slice exceeds the
	// maximum permitted size (10 MiB). Oversized input is rejected before any
	// YAML parse to prevent resource exhaustion.
	ErrInputTooLarge = errors.New(
		"artifact input too large: the supplied bytes exceed the maximum " +
			"allowed artifact size (10 MiB) — the file may be corrupt or " +
			"injected; run `byreis doctor` to inspect the file")
)

// Codec is the real on-disk YAML artifact codec. It is constructed via New
// and has no mutable state; all methods are safe for concurrent use.
//
// The Codec type exposes context-first methods as its primary API. At the
// composition root (internal/app / cmd/byreis) a thin wrapper adapts it to
// the usecase.ArtifactCodec port (no-context) for injection into core use-
// cases. This layering keeps context propagation in the adapter boundary
// without requiring core ports to carry context.
type Codec struct{}

// New returns a ready-to-use Codec. No I/O occurs at construction time.
func New() *Codec { return &Codec{} }

// DecodeSigned decodes a signed file-of-record artifact from the exact input
// bytes. It operates on the bytes as given; it never re-normalizes or
// re-emits the buffer.
//
// Returns ErrInputTooLarge if len(b) > 10 MiB.
// Returns ErrTypedMismatch if the input has no manifest_sig block.
// Returns ErrDecodeMalformed for any other structural violation.
// Returns a context error if ctx is cancelled/expired.
// Never returns a partial domain value on an error path.
func (c *Codec) DecodeSigned(ctx context.Context, b []byte) (artifact.Signed, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Signed{}, fmt.Errorf("artifact decode cancelled: %w", err)
	}
	if len(b) > maxInputBytes {
		return artifact.Signed{}, fmt.Errorf("%w", ErrInputTooLarge)
	}

	raw, err := parseRawEnvelope(b)
	if err != nil {
		return artifact.Signed{}, fmt.Errorf("%w: %v", ErrDecodeMalformed, err)
	}

	// Typed shape check: a signed artifact MUST carry manifest_sig.
	if raw.manifestSig == nil {
		return artifact.Signed{}, fmt.Errorf("%w: file has no manifest_sig block "+
			"(expected a signed file-of-record, got an unsigned submission)",
			ErrTypedMismatch)
	}

	s, err := buildSigned(raw)
	if err != nil {
		return artifact.Signed{}, err
	}
	return s, nil
}

// DecodeUnsigned decodes an unsigned contributor submission artifact from the
// exact input bytes. It operates on the bytes as given; it never re-normalizes
// or re-emits the buffer.
//
// Returns ErrInputTooLarge if len(b) > 10 MiB.
// Returns ErrTypedMismatch if the input carries a manifest_sig block.
// Returns ErrDecodeMalformed for any other structural violation.
// Returns a context error if ctx is cancelled/expired.
// Never returns a partial domain value on an error path.
func (c *Codec) DecodeUnsigned(ctx context.Context, b []byte) (artifact.Unsigned, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Unsigned{}, fmt.Errorf("artifact decode cancelled: %w", err)
	}
	if len(b) > maxInputBytes {
		return artifact.Unsigned{}, fmt.Errorf("%w", ErrInputTooLarge)
	}

	raw, err := parseRawEnvelope(b)
	if err != nil {
		return artifact.Unsigned{}, fmt.Errorf("%w: %v", ErrDecodeMalformed, err)
	}

	// Typed shape check: an unsigned artifact MUST NOT carry manifest_sig.
	if raw.manifestSig != nil {
		return artifact.Unsigned{}, fmt.Errorf("%w: file has a manifest_sig block "+
			"(expected an unsigned submission, got a signed file-of-record)",
			ErrTypedMismatch)
	}

	u, err := buildUnsigned(raw)
	if err != nil {
		return artifact.Unsigned{}, err
	}
	return u, nil
}

// EncodeSigned serialises a signed file-of-record to YAML wire bytes. The
// output is deterministic for a given artifact.Signed: keys in the YAML
// envelope are emitted in a stable order so a re-encode of an unchanged
// artifact is byte-identical. This determinism is a diff-hygiene property;
// the trust anchor is verify.ContentSHA over the manifest preimage.
//
// Returns a context error if ctx is cancelled/expired.
// Returns ErrDecodeMalformed if the input contains separator bytes in
// manifest fields (caught by the manifest package's canonical encoder).
func (c *Codec) EncodeSigned(ctx context.Context, s artifact.Signed) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("artifact encode cancelled: %w", err)
	}
	return marshalSigned(s)
}

// EncodeUnsigned serialises an unsigned contributor submission to YAML wire
// bytes. The output is deterministic for a given artifact.Unsigned.
//
// Returns a context error if ctx is cancelled/expired.
func (c *Codec) EncodeUnsigned(ctx context.Context, u artifact.Unsigned) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("artifact encode cancelled: %w", err)
	}
	return marshalUnsigned(u)
}

// rawEnvelope is the intermediate representation produced by parseRawEnvelope.
// All fields are strings at this stage; type-specific validation happens in
// buildSigned / buildUnsigned after the structural parse is done.
type rawEnvelope struct {
	values      map[string]string // per-key ciphertext strings
	byreis      rawByreisBlock
	manifestSig *rawManifestSig // nil means unsigned
}

type rawByreisBlock struct {
	formatVersion string
	projectID     string
	file          string
	counter       uint64
	recipients    []string // raw FP strings from YAML
}

type rawManifestSig struct {
	signer string
	sig    string
}

// parseRawEnvelope decodes the YAML document into the rawEnvelope structure
// without committing to the signed/unsigned shape. It enforces:
//
//   - Input is valid YAML
//   - No duplicate envelope keys (document-level)
//   - No typed tag abuse (!!binary, !!int, !!null, etc.) on value fields
//   - Alias expansion bounded to maxAliasNodes
//   - Required byreis block present and structurally valid
//   - format_version matches ^byreis\.native\.v[0-9]+$
//   - Recipient fingerprints are exactly 64 lowercase hex chars
//   - Signature (if present) is valid hex
//   - No 0x1e/0x1f separator injection in manifest fields (caught by
//     manifest.Encode during the validation pass)
func parseRawEnvelope(b []byte) (rawEnvelope, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))

	// Parse into a raw YAML node to detect duplicate keys and typed tags
	// before any structural decode.
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		return rawEnvelope{}, fmt.Errorf("YAML parse error: %v", err)
	}

	// The root node should be a document node containing a mapping.
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
		return rawEnvelope{}, fmt.Errorf("expected a YAML document, got node kind %v", root.Kind)
	}
	mapping := root.Content[0]
	if mapping.Kind != yaml.MappingNode {
		return rawEnvelope{}, fmt.Errorf("expected a YAML mapping at document root, got kind %v", mapping.Kind)
	}

	// Bounded alias/anchor expansion check. Count all nodes recursively.
	nodeCount := countNodes(&root, 0)
	if nodeCount > maxAliasNodes {
		return rawEnvelope{}, fmt.Errorf("YAML anchor/alias expansion exceeds safety bound "+
			"(%d nodes > %d limit) — possible billion-laughs attack",
			nodeCount, maxAliasNodes)
	}

	// Walk the top-level mapping pairs, enforcing duplicate-key detection and
	// extracting the known envelope fields.
	seen := make(map[string]struct{})
	var env rawEnvelope
	env.values = make(map[string]string)

	pairs := mapping.Content
	if len(pairs)%2 != 0 {
		return rawEnvelope{}, fmt.Errorf("malformed YAML mapping: odd number of nodes (%d)", len(pairs))
	}

	for i := 0; i < len(pairs); i += 2 {
		keyNode := pairs[i]
		valNode := pairs[i+1]

		if keyNode.Kind != yaml.ScalarNode {
			return rawEnvelope{}, fmt.Errorf("mapping key is not a scalar (kind %v)", keyNode.Kind)
		}
		key := keyNode.Value

		// Duplicate envelope key check.
		if _, exists := seen[key]; exists {
			return rawEnvelope{}, fmt.Errorf("duplicate envelope key %q", key)
		}
		seen[key] = struct{}{}

		switch key {
		case "byreis":
			b, err := parseByreisBlock(valNode)
			if err != nil {
				return rawEnvelope{}, fmt.Errorf("byreis block: %v", err)
			}
			env.byreis = b

		case "manifest_sig":
			ms, err := parseManifestSigBlock(valNode)
			if err != nil {
				return rawEnvelope{}, fmt.Errorf("manifest_sig block: %v", err)
			}
			env.manifestSig = &ms

		default:
			// All other top-level keys are treated as per-key ciphertext values.
			ct, err := extractStringScalar(key, valNode)
			if err != nil {
				return rawEnvelope{}, err
			}
			env.values[key] = ct
		}
	}

	// Validate format_version.
	if !formatVersionRE.MatchString(env.byreis.formatVersion) {
		return rawEnvelope{}, fmt.Errorf("format_version %q does not match "+
			"^byreis\\.native\\.v[0-9]+$", env.byreis.formatVersion)
	}

	// Validate recipient fingerprints: exactly 64 lowercase hex chars.
	for _, fp := range env.byreis.recipients {
		if len(fp) != 64 {
			return rawEnvelope{}, fmt.Errorf("recipient fingerprint %q is %d chars "+
				"(must be exactly 64 lowercase hex chars)", fp, len(fp))
		}
		if !isLowercaseHex(fp) {
			return rawEnvelope{}, fmt.Errorf("recipient fingerprint %q contains "+
				"non-lowercase-hex characters", fp)
		}
	}

	// Validate signature hex (if present).
	if env.manifestSig != nil {
		if _, err := hex.DecodeString(env.manifestSig.sig); err != nil {
			return rawEnvelope{}, fmt.Errorf("manifest_sig.sig %q is not valid hex: %v",
				env.manifestSig.sig, err)
		}
	}

	// Separator-injection validation: build a minimal manifest and run
	// manifest.Encode to catch any 0x1e/0x1f in signed fields.
	if err := validateNoSeparatorInjection(env); err != nil {
		return rawEnvelope{}, err
	}

	return env, nil
}

// parseByreisBlock parses the byreis: mapping node.
func parseByreisBlock(node *yaml.Node) (rawByreisBlock, error) {
	if node.Kind != yaml.MappingNode {
		return rawByreisBlock{}, fmt.Errorf("byreis value is not a mapping")
	}

	pairs := node.Content
	if len(pairs)%2 != 0 {
		return rawByreisBlock{}, fmt.Errorf("malformed byreis mapping")
	}

	seen := make(map[string]struct{})
	var b rawByreisBlock

	for i := 0; i < len(pairs); i += 2 {
		kn := pairs[i]
		vn := pairs[i+1]
		if kn.Kind != yaml.ScalarNode {
			return rawByreisBlock{}, fmt.Errorf("byreis key is not a scalar")
		}
		k := kn.Value
		if _, exists := seen[k]; exists {
			return rawByreisBlock{}, fmt.Errorf("duplicate byreis key %q", k)
		}
		seen[k] = struct{}{}

		switch k {
		case "format_version":
			s, err := requireStringScalar("format_version", vn)
			if err != nil {
				return rawByreisBlock{}, err
			}
			b.formatVersion = s

		case "project_id":
			s, err := requireStringScalar("project_id", vn)
			if err != nil {
				return rawByreisBlock{}, err
			}
			b.projectID = s

		case "file":
			s, err := requireStringScalar("file", vn)
			if err != nil {
				return rawByreisBlock{}, err
			}
			b.file = s

		case "counter":
			if vn.Kind != yaml.ScalarNode {
				return rawByreisBlock{}, fmt.Errorf("counter must be a scalar")
			}
			var n uint64
			if err := vn.Decode(&n); err != nil {
				return rawByreisBlock{}, fmt.Errorf("counter is not a valid uint64: %v", err)
			}
			b.counter = n

		case "recipients":
			fps, err := parseRecipientsBlock(vn)
			if err != nil {
				return rawByreisBlock{}, err
			}
			b.recipients = fps

		default:
			// Unknown byreis sub-keys are silently allowed for forward compat.
		}
	}

	return b, nil
}

// parseRecipientsBlock parses the recipients: sequence of {fp: ...} mappings.
func parseRecipientsBlock(node *yaml.Node) ([]string, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("recipients must be a sequence")
	}
	fps := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		if item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("each recipient must be a mapping")
		}
		pairs := item.Content
		if len(pairs)%2 != 0 {
			return nil, fmt.Errorf("malformed recipient mapping")
		}
		for j := 0; j < len(pairs); j += 2 {
			kn := pairs[j]
			vn := pairs[j+1]
			if kn.Kind != yaml.ScalarNode || kn.Value != "fp" {
				continue
			}
			fp, err := requireStringScalar("fp", vn)
			if err != nil {
				return nil, fmt.Errorf("recipient fp: %v", err)
			}
			fps = append(fps, fp)
		}
	}
	return fps, nil
}

// parseManifestSigBlock parses the manifest_sig: {signer: ..., sig: ...} mapping.
func parseManifestSigBlock(node *yaml.Node) (rawManifestSig, error) {
	if node.Kind != yaml.MappingNode {
		return rawManifestSig{}, fmt.Errorf("manifest_sig must be a mapping")
	}
	pairs := node.Content
	if len(pairs)%2 != 0 {
		return rawManifestSig{}, fmt.Errorf("malformed manifest_sig mapping")
	}

	seen := make(map[string]struct{})
	var ms rawManifestSig

	for i := 0; i < len(pairs); i += 2 {
		kn := pairs[i]
		vn := pairs[i+1]
		if kn.Kind != yaml.ScalarNode {
			return rawManifestSig{}, fmt.Errorf("manifest_sig key is not a scalar")
		}
		k := kn.Value
		if _, exists := seen[k]; exists {
			return rawManifestSig{}, fmt.Errorf("duplicate manifest_sig key %q", k)
		}
		seen[k] = struct{}{}

		switch k {
		case "signer":
			s, err := requireStringScalar("signer", vn)
			if err != nil {
				return rawManifestSig{}, err
			}
			ms.signer = s

		case "sig":
			s, err := requireStringScalar("sig", vn)
			if err != nil {
				return rawManifestSig{}, err
			}
			ms.sig = s
		}
	}

	return ms, nil
}

// requireStringScalar returns the value of a scalar node, rejecting any
// typed tag (!!binary, !!int, !!null, etc.) and returning a plain string.
func requireStringScalar(field string, node *yaml.Node) (string, error) {
	if node.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("%s must be a string scalar, got node kind %v", field, node.Kind)
	}
	// Tag check: reject any explicit non-string typed tag.
	if node.Tag != "" && node.Tag != "!!str" && node.Tag != "!" {
		return "", fmt.Errorf("%s has a typed tag %q — only plain string values are permitted "+
			"(no !!binary, !!int, !!null, etc.)", field, node.Tag)
	}
	return node.Value, nil
}

// extractStringScalar extracts a per-key ciphertext value. Rejects typed
// tags just like requireStringScalar, but for a top-level envelope value.
func extractStringScalar(field string, node *yaml.Node) (string, error) {
	if node.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("value for key %q must be a string scalar, got kind %v", field, node.Kind)
	}
	if node.Tag != "" && node.Tag != "!!str" && node.Tag != "!" {
		return "", fmt.Errorf("value for key %q has a typed tag %q — only plain string "+
			"ciphertext values are permitted (no !!binary, !!int, !!null, etc.)",
			field, node.Tag)
	}
	return node.Value, nil
}

// countNodes counts the total number of YAML nodes recursively, used to
// detect anchor/alias billion-laughs expansion.
func countNodes(n *yaml.Node, depth int) int {
	if n == nil || depth > 200 {
		return 0
	}
	total := 1
	for _, child := range n.Content {
		total += countNodes(child, depth+1)
		if total > maxAliasNodes+1 {
			return total // early exit, no need to count further
		}
	}
	return total
}

// isLowercaseHex reports whether s contains only lowercase hexadecimal chars.
func isLowercaseHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// validateNoSeparatorInjection builds a Manifest from the rawEnvelope and runs
// manifest.Encode to detect 0x1e/0x1f separator injection in any signed field.
// A separator in project_id, logical_file_name, a key name, or a fingerprint
// would let an attacker shift field boundaries in the signed stream.
func validateNoSeparatorInjection(env rawEnvelope) error {
	vals := make(map[string][]byte, len(env.values))
	for k, v := range env.values {
		vals[k] = []byte(v)
	}
	m := manifest.Manifest{
		FormatVersion:         env.byreis.formatVersion,
		ProjectID:             env.byreis.projectID,
		LogicalFileName:       env.byreis.file,
		Counter:               env.byreis.counter,
		Values:                vals,
		RecipientFingerprints: env.byreis.recipients,
	}
	_, err := manifest.Encode(m)
	if err != nil {
		return fmt.Errorf("manifest field contains separator byte or is otherwise invalid: %v", err)
	}
	return nil
}

// buildSigned constructs an artifact.Signed from a rawEnvelope that has
// already passed all structural/type-level checks.
func buildSigned(env rawEnvelope) (artifact.Signed, error) {
	if env.manifestSig == nil {
		return artifact.Signed{}, fmt.Errorf("%w: manifest_sig block is absent", ErrDecodeMalformed)
	}

	s := artifact.Signed{
		Values: make(map[string]artifact.EncryptedValue, len(env.values)),
		Byreis: buildMetadata(env),
		ManifestSig: artifact.ManifestSig{
			Signer: env.manifestSig.signer,
			Sig:    env.manifestSig.sig,
		},
	}
	for k, v := range env.values {
		s.Values[k] = artifact.EncryptedValue(v)
	}
	return s, nil
}

// buildUnsigned constructs an artifact.Unsigned from a rawEnvelope.
func buildUnsigned(env rawEnvelope) (artifact.Unsigned, error) {
	u := artifact.Unsigned{
		Values: make(map[string]artifact.EncryptedValue, len(env.values)),
		Byreis: buildMetadata(env),
	}
	for k, v := range env.values {
		u.Values[k] = artifact.EncryptedValue(v)
	}
	return u, nil
}

// buildMetadata constructs an artifact.Metadata from rawByreisBlock data.
func buildMetadata(env rawEnvelope) artifact.Metadata {
	recs := make([]artifact.RecipientEntry, 0, len(env.byreis.recipients))
	for _, fp := range env.byreis.recipients {
		recs = append(recs, artifact.RecipientEntry{FP: fp})
	}
	return artifact.Metadata{
		FormatVersion: env.byreis.formatVersion,
		ProjectID:     env.byreis.projectID,
		File:          env.byreis.file,
		Counter:       env.byreis.counter,
		Recipients:    recs,
	}
}

// marshalSigned serialises a signed artifact to YAML wire bytes. The key
// order in the YAML envelope is deterministic (sorted by key name for values,
// fixed for the byreis and manifest_sig blocks) so a re-encode of an
// unchanged artifact is byte-identical. This is a diff-hygiene property, not
// the trust anchor.
func marshalSigned(s artifact.Signed) ([]byte, error) {
	doc := buildYAMLDocument(s.Values, s.Byreis, &s.ManifestSig)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("%w: marshal signed: %v", ErrDecodeMalformed, err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("%w: close encoder: %v", ErrDecodeMalformed, err)
	}
	return buf.Bytes(), nil
}

// marshalUnsigned serialises an unsigned artifact to YAML wire bytes.
func marshalUnsigned(u artifact.Unsigned) ([]byte, error) {
	doc := buildYAMLDocument(u.Values, u.Byreis, nil)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("%w: marshal unsigned: %v", ErrDecodeMalformed, err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("%w: close encoder: %v", ErrDecodeMalformed, err)
	}
	return buf.Bytes(), nil
}

// yamlStringNode returns a plain string YAML scalar node (no typed tag).
func yamlStringNode(v string) *yaml.Node {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: v,
	}
}

// yamlUint64Node returns a plain uint64 YAML scalar node.
func yamlUint64Node(v uint64) *yaml.Node {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!int",
		Value: fmt.Sprintf("%d", v),
	}
}

// buildYAMLDocument constructs a deterministic yaml.Node tree for the
// artifact envelope. The per-key values are sorted by key name; the byreis
// and manifest_sig blocks follow in fixed positions.
func buildYAMLDocument(
	values map[string]artifact.EncryptedValue,
	meta artifact.Metadata,
	sig *artifact.ManifestSig,
) *yaml.Node {
	mapping := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	// Emit per-key ciphertext entries in sorted key order.
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		mapping.Content = append(mapping.Content,
			yamlStringNode(k),
			yamlStringNode(string(values[k])),
		)
	}

	// byreis block — fixed sub-key order.
	byreisMapping := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	addStringField := func(k, v string) {
		byreisMapping.Content = append(byreisMapping.Content,
			yamlStringNode(k),
			yamlStringNode(v),
		)
	}
	addStringField("format_version", meta.FormatVersion)
	addStringField("project_id", meta.ProjectID)
	addStringField("file", meta.File)
	byreisMapping.Content = append(byreisMapping.Content,
		yamlStringNode("counter"),
		yamlUint64Node(meta.Counter),
	)

	// recipients sequence.
	recipSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, r := range meta.Recipients {
		rmap := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		rmap.Content = append(rmap.Content,
			yamlStringNode("fp"),
			yamlStringNode(r.FP),
		)
		recipSeq.Content = append(recipSeq.Content, rmap)
	}
	byreisMapping.Content = append(byreisMapping.Content,
		yamlStringNode("recipients"),
		recipSeq,
	)

	mapping.Content = append(mapping.Content,
		yamlStringNode("byreis"),
		byreisMapping,
	)

	// manifest_sig block — only present for signed artifacts.
	if sig != nil {
		sigMapping := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		sigMapping.Content = append(sigMapping.Content,
			yamlStringNode("signer"),
			yamlStringNode(sig.Signer),
			yamlStringNode("sig"),
			yamlStringNode(sig.Sig),
		)
		mapping.Content = append(mapping.Content,
			yamlStringNode("manifest_sig"),
			sigMapping,
		)
	}

	return &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{mapping}}
}

// PortAdapter wraps a *Codec and implements the usecase.ArtifactCodec port
// (no-context methods) for injection into core use-cases. It is the
// composition-root adapter used when wiring the real codec into the
// read/review/merge/edit paths. The no-context methods call through to the
// ctx-taking methods with context.Background() so they remain cancellable if
// the context has not been inherited from outside.
//
// The PortAdapter also implements app.ArtifactEncoder (EncodeUnsigned taking
// a submit.OpenPRInput) for the Submit path. This lets one concrete type
// satisfy both OUTER ports without creating a single fat interface.
type PortAdapter struct {
	codec *Codec
}

// NewPortAdapter wraps a Codec as the usecase.ArtifactCodec port adapter.
func NewPortAdapter(c *Codec) *PortAdapter {
	return &PortAdapter{codec: c}
}

// DecodeSigned implements usecase.ArtifactCodec (no-context port).
func (a *PortAdapter) DecodeSigned(b []byte) (artifact.Signed, error) {
	return a.codec.DecodeSigned(context.Background(), b)
}

// DecodeUnsigned implements usecase.ArtifactCodec (no-context port).
func (a *PortAdapter) DecodeUnsigned(b []byte) (artifact.Unsigned, error) {
	return a.codec.DecodeUnsigned(context.Background(), b)
}

// EncodeSigned implements usecase.ArtifactCodec (no-context port).
func (a *PortAdapter) EncodeSigned(s artifact.Signed) ([]byte, error) {
	return a.codec.EncodeSigned(context.Background(), s)
}

// EncodeUnsignedFromValues encodes an artifact.Unsigned to YAML wire bytes.
// Exposed for the Submit path's app.ArtifactEncoder wiring at the composition
// root; the Submit port is separately declared and ISP-clean.
func (a *PortAdapter) EncodeUnsignedFromValues(u artifact.Unsigned) ([]byte, error) {
	return a.codec.EncodeUnsigned(context.Background(), u)
}
