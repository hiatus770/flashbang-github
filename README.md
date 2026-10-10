# Flashbang

Flashbang listens for Anchor desktop notifications and runs lighting effects
on selected OpenRGB devices when a notification matches a regular expression.

## Requirements

- Rust with support for edition 2024.
- The Protocol Buffers compiler (`protoc`) for building the Anchor SDK.
- Anchor desktop running on the same machine.
- OpenRGB with its SDK server enabled on TCP port 6742.

The Rust clients and Anchor protocol schemas are included under `vendor/`.

## Run

```sh
cargo run -- --check-anchor
cargo run
```

The first command checks the Anchor connection and notification subscription
without running lighting effects. Approve pairing in Anchor if prompted.

On first normal startup, Flashbang creates a configuration file in the system
configuration directory, typically `~/.config/flashbang/flashbang.yaml` on Linux.
Edit that file and replace `Your OpenRGB device name` with the exact device name
shown in OpenRGB, then restart Flashbang. `config.yaml` contains the defaults.

The supplied Discord and Signal rules use `(?i)` for case-insensitive substring
matching and the built-in `blink_red` effect. Rules examine the application ID,
application name, notification title, and body. The first matching rule runs.

Anchor discovery first checks UDP port 5028, then falls back to the
`_anchor._udp.local.` mDNS advertisement for desktop versions without a probe
responder. The SDK connection uses the advertised port, normally UDP 5027.

## Development

```sh
cargo check --locked
cargo test --locked --bin flashbang
```

## License

Original Flashbang source is licensed under [MIT](LICENSE). Bundled dependencies
retain their GPL licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).
