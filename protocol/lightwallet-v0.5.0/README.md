# Pinned light-wallet wire schema

Source: [zcash/lightwallet-protocol v0.5.0](https://github.com/zcash/lightwallet-protocol/tree/ac7cee052a1bf5d430985a478d39e8b513fc4bd4), commit `ac7cee052a1bf5d430985a478d39e8b513fc4bd4`.

The `.proto` files and MIT license are unmodified copies. `src/lightwallet/wire.rs` is a narrow Rust/prost transcription of their message definitions used by the read-only adapter. It retains the original protobuf field numbers, including Ironwood action (9), tree-size (3), tree-state (7), and protocol-version (18) fields. No generated gRPC service or build-time `protoc` dependency is required. Unsupported service methods are absent from the client.

The compact projection follows the pinned Zakura verbose `getblock` RPC: transactions are selected when any Sapling, Orchard, or Ironwood shielded elements exist; txids are reversed into wire order; encrypted output ciphertexts are truncated to 52 bytes. Block hashes use little-endian bytes; `TreeState.hash` uses display hexadecimal. These are transport projections, not consensus or proof verification.

Copies:

- `service.proto` SHA-256 `6fbfa974081fb02366a3118a25764af289bdbb86688978f5ff2bae661dfa346a`.
- `compact_formats.proto` SHA-256 `d8d0c8aaa5ceec7d5dcc188ef25b04011df2ec0254901620fce982fc13aeb32d`.
- `LICENSE` SHA-256 `507b5839562468f41e887d6153e185b8c47e9a48dcbd09a25049fb22b98d497b`.
