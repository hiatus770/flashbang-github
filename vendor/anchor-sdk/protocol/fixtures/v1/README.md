# Protocol v1 fixtures

These files are shared wire-format examples. SDKs should decode the same bytes
and apply the same result. A fixture is not a snapshot of one SDK's objects.

## Files

- `control/*.textproto` is the readable protobuf input.
- The matching `control/*.hex` file is the encoded control record. It contains
  lowercase hexadecimal with no spaces or `0x` prefixes.
- `manifest.json` lists each case and its expected result. Cases without a
  `source` and `wire` file are validation requirements that still need tests.

Control records start with `ANCR`, followed by the protocol major byte, minor
byte, an unsigned-varint payload length, and one length-delimited
`ControlEnvelope`. The current fixtures target `anchor/1.0`.

## Add or change a fixture

1. Confirm that the message and its rules are documented in the v1 `.proto`
   files and `anchor-sdk/protocol/README.md`.
2. Add a readable `.textproto` file under `control/`.
3. Encode the complete record and save the bytes as the matching `.hex` file.
4. Add the case to `manifest.json`, including the expected result.
5. Include accepted and rejected cases when adding a new protocol rule.
6. Update SDK conformance tests so they load and check the fixture.

Do not add provisional wire formats. Add QR or datagram fixtures only after
their binary layout, size limits, and validation rules are defined.

## Check your changes

From the repository root, run the Rust SDK tests:

```sh
cargo test --manifest-path anchor-sdk/rust/Cargo.toml
```

The Rust tests currently decode the three open-operation `.hex` fixtures and
round-trip the pairing-reject record. Kotlin and Swift do not yet load this
directory automatically, so new fixtures must not be treated as cross-SDK
coverage until tests are added for them.

When changing a `.proto` file, regenerate bindings for each SDK and run that
SDK's tests in the same change.
