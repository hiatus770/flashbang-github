# Anchor Protocol v1

This directory is the source of truth for the Anchor wire protocol. The Rust,
Kotlin, and Swift SDKs generate their protobuf message types from these files.
Generated code is not edited by hand.

## What the protocol covers

Anchor runs over mutually authenticated QUIC. The TLS ALPN is `anchor/1`.
After TLS, the peers use one ordered control stream. Its first bytes are:

```text
ANCR + major:u8 + minor:u8 + unsigned-varint length + ControlEnvelope
```

Each control record is a length-delimited protobuf `ControlEnvelope`. The
envelope carries pairing, session, capability, reliable-stream, datagram-flow,
and error messages.

The schemas are grouped as follows:

- `common.proto`: node IDs, protocol versions, display information, and errors.
- `pairing.proto`: short-lived invitations and user approval or rejection.
- `session.proto`: normal-session hello/ready, ping/pong, and close.
- `capability.proto`: endpoint advertisements, capability sessions, and typed
  capability records.
- `stream.proto`: binding a QUIC stream to a capability session.
- `datagram.proto`: negotiating a capability's QUIC datagram flow.
- `capabilities/*.proto`: feature messages for camera, clipboard, commands,
  device state, files, input, media, notifications, screen, and SMS.

Feature data is typed. A `CapabilityRecord` is accepted only when its exact
protobuf type URL was advertised for the capability session. File and video
payloads use separately negotiated QUIC streams or datagram flows; they are not
embedded in the control envelope.

## v1 wire rules

- The current wire version is `1.0`. The SDK accepts the `ANCR` preface for
  major version `1`; it accepts any minor at or below its own and rejects a
  peer whose minor is ahead of its own. See [`VERSIONING.md`](VERSIONING.md)
  for the full version-bump policy.
- A request has a non-zero `request_id`. Its reply has `response_to` set to
  that ID. Notifications set both fields to zero. Both fields must not be set
  together.
- A normal session starts with `SessionHello` and `SessionReady`. Pairing-only
  connections use `PairingHello` and do not advertise capabilities.
- A capability must be advertised before it is opened. Its name and major
  version identify the capability contract independently of the protocol
  version.
- A capability session must be opened before records, streams, or datagram
  flows use it. A closed session accepts no further records.
- `StreamOpen` binds an existing QUIC stream to a negotiated type URL. The
  opener waits for `StreamOpened` before sending application bytes.
- Datagrams are negotiated with `DatagramFlowOpen`. Their fixed binary payload
  headers are defined by the owning capability implementation, not protobuf.
- Field numbers are permanent. Do not change a field's wire type. When a field
  is removed, reserve its number and name. Add optional fields for compatible
  v1 changes.
- Do not add generic JSON, `Any`, maps, or anonymous application bytes to the
  control plane. Every application payload needs an explicit schema and
  negotiated type URL.
- Control records are limited to 1 MiB. Individual messages define their own
  required lengths and bounds; SDKs enforce those limits before allocating or
  dispatching data.

## Trust and security

`NodeId` is a 32-byte identifier derived from a public identity key. It is a
routing and display identifier, not proof of identity. Trust comes from the
TLS certificate pin stored for a paired peer.

Pairing invitations are short-lived route hints, not credentials. Before a
pairing invitation is used, validate its protocol version, IDs, expiry,
certificate fingerprint, certificate size, and nonce. During pairing, verify
the presented certificate and the transcript hash. Persist a certificate pin
only after the user approves the pairing. The short authentication string is
derived locally and is not sent on the wire.

Capability authorization is a host-policy decision. Authentication alone does
not grant access to input, files, SMS, camera, screen capture, or other
capabilities. Providers must enforce their platform permissions and local
policy. Protocol error messages may contain concise diagnostics, but never
credentials, private paths, payloads, or stack traces.

## Fixtures and changes

`fixtures/v1` contains language-neutral conformance cases:

- `control/*.textproto` is the readable protobuf input.
- The matching `.hex` file is the expected complete `ANCR` control prefix and
  length-delimited envelope, encoded as lowercase hexadecimal.
- `manifest.json` records the expected result, including rejected inputs.

When changing the protocol:

1. Update the schema and this README in the same change.
2. Add or update accepted and rejected fixture cases.
3. Regenerate bindings from a clean checkout. Rust generates during its build;
   Kotlin runs `protoc` from its Gradle build; Swift uses
   `swift/scripts/generate-protobuf.sh`.
4. Run the SDK tests and cross-language conformance checks before using the
   change in an application.

For a quick Rust validation, run:

```sh
cd anchor-sdk/rust
cargo test
```

Do not add a fixture for an undocumented or provisional wire format. Binary QR
and datagram fixtures belong here only after their layout, size limits, and
accepted and rejected cases are defined.
