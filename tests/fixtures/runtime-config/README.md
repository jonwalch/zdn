# Runtime configuration vectors

`addresses.json` was originally generated with independent Python integer
arithmetic and `hashlib`. The test-only Rust reference in
`tests/reference_vectors.rs` reproduces those exact bytes using base-256 long
division and `ring` SHA-256. It does not call the production renderer, `bs58`,
or `sha2`.
The version bytes match `zakura-protocol` 2.2.0
`src/constants/{mainnet,testnet}.rs`, used by the inspected Zakura source.

The accepted vectors cover both transparent Testnet address forms with zero,
ascending, and all-ones 20-byte payloads. Rejected vectors have valid checksums
but use other networks, unknown versions, or wrong payload lengths.
These are synthetic hash payloads, not wallet keys. Passing them establishes
address-format handling only; it does not establish ownership, mining support,
or shielded payment support.

Check all independent references with `cargo test --locked --test reference_vectors`.
To explicitly regenerate, run
`cargo test --locked --test reference_vectors regenerate -- --ignored` from the
`zdn` repository. Generation and checks do not require Python.
