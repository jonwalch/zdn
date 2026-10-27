# Synthetic consensus manifest vector

These fixtures test the offline manifest contract. Their block hashes, byte
digests, lengths, magic, and parameters are illustrative. They do not identify
real blocks or a qualified chain. They provide no Zakura, wallet, mining, or
Ironwood compatibility evidence.

`valid.json` gives all required fields and explicit optional values. It includes
one zero-value lockbox output to exercise the explicit NU6.1 output contract;
the destination is synthetic and does not establish a usable funding recipe.
`canonical.json` contains the normalized object as compact JSON with recursively
sorted keys and no trailing newline. The empty checkpoint list resolves to the
genesis checkpoint.

The canonical byte sequence is the ASCII prefix `zdn-consensus/v1alpha1`, one NUL
byte, then the exact bytes of `canonical.json`. `sha256.txt` gives its lowercase
SHA-256 digest. It was computed independently with Python's standard library,
without calling the Rust implementation.

The test-only Rust reference in `tests/reference_vectors.rs` now reproduces the
original bytes with `ring` SHA-256, independent of production's `sha2` and manifest
normalization. It applies the documented defaults to this one fixed fixture;
it does not validate a recipe or construct consensus blocks.

Check all reference vectors from the repository root:

```sh
cargo test --locked --test reference_vectors
```

Explicitly regenerate all four expected files (ordinary tests never write them):

```sh
cargo test --locked --test reference_vectors regenerate -- --ignored
```
