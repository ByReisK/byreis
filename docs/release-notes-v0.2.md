# byreis v0.2 release notes

## Migration: counter-store format change

byreis v0.2 extends the registry-side counter store JSON with a new
field that records each file's rotation epoch. Once an admin running
v0.2 lands the first rotation in a project, the counter store for that
project includes this field, and a v0.1 binary will not be able to
read it (the v0.1 decoder uses a strict-unknown-field rejection
posture). All admin operators must upgrade to v0.2 before the first
rotation commit lands; there is no rollback path from a registry that
has seen any rotation. Pre-rotation counter stores are forward-
compatible (v0.2 reads v0.1 fine).
