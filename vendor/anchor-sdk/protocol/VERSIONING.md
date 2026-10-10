# Versioning and compatibility

Anchor has three independent version numbers. Each answers a different
question. A change to the protocol or an SDK must identify which of them it
affects — a change can move one without moving the others.

## The three numbers

### 1. Protocol major and minor (`PROTOCOL_MAJOR`, `PROTOCOL_MINOR`)

Defined once per SDK (`anchor-sdk/rust/src/lib.rs`, and mirrored in
`anchor-sdk/kotlin/.../AnchorSession.kt` and `AnchorProtocol.kt`) and sent in
the `ANCR` control preface and in `SessionHello`/`SessionReady`. This is the
control-envelope and session-negotiation layer: framing, the pairing
handshake, and how a session is established.

- **Bump major** for any change that is not safely ignorable by an older
  peer: different framing, a different handshake sequence, or a change in
  meaning of an existing negotiation message. A major mismatch is a hard,
  immediate connection failure — peers on different majors never connect.
- **Bump minor** for a backward-compatible addition to the control layer
  (for example, a new optional `ControlEnvelope` body variant that older
  peers can safely ignore). A peer accepts any minor at or below its own; it
  rejects a peer whose minor is *ahead* of its own, since that peer may rely
  on control-layer behavior it doesn't understand yet. This is why desktop
  and phone builds that are momentarily out of sync (a Play Store rollout in
  progress, for example) still interoperate as long as neither has moved to
  a new major.

### 2. Per-capability major (e.g. `org.anchor.camera` major `1`)

Each capability (`anchor-sdk/protocol/anchor/v1/capabilities/*.proto`)
advertises its own major version, independent of the protocol major and of
every other capability. Opening a capability requires an exact name+major
match on both peers — there is no negotiation to an older major.

- **Bump a capability's major** for an incompatible change to that
  capability's schema or semantics: a field's wire type changes, a field's
  meaning changes, or a required field is added.
- **Do not bump it** for a compatible addition: a new optional field, or a
  new record type URL added to the capability's advertisement. Field-number
  and wire-type rules are in `anchor-sdk/protocol/README.md` — follow those
  first; the capability major only moves when that policy is actually
  violated.
- A capability being unavailable (major mismatch, or not advertised at all)
  is a normal, expected outcome — the SDK surfaces it as
  `CapabilityUnavailable`, not a connection failure.

### 3. SDK package version (crate version, Gradle artifact version, Swift tag)

Ordinary semver against that SDK's own public Rust/Kotlin/Swift API — the
capability-module functions and record types a consuming application calls
directly. This moves independently of the two numbers above: renaming a
public SDK record field is a breaking package change even when nothing on
the wire moved, and a wire-compatible internal refactor is not a breaking
package change at all.

## Which number does my change bump?

| Change | Protocol major/minor | Capability major | SDK package version |
| --- | --- | --- | --- |
| New optional field on an existing capability message | no | no | minor/patch |
| New capability record type URL | no | no | minor |
| Field wire type changed, or a field's meaning changed | no | **yes** | major |
| New optional `ControlEnvelope` body variant | minor | n/a | minor |
| Pairing handshake or control framing changes incompatibly | **major** | n/a | major |
| Renamed or restructured a public Rust/Kotlin/Swift record type | no (if wire unchanged) | no (if wire unchanged) | **major** |

When in doubt, prefer the smaller bump that is still honest about the
change: a compatible addition should never force a major bump anywhere.

## What this does not cover yet

External, tagged consumption of the Rust and Kotlin SDKs (so a version
number is meaningful outside this monorepo) is a separate, not-yet-started
piece of work. Until then, these numbers are enforced only within this
repository's own build and tests.
