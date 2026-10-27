# Saved genesis and seed bytes

`chain import` saves declared genesis and seed bytes in one bundle. `chain verify`
checks that bundle again against an expected consensus manifest. Both commands
run offline. They need no AWS credentials, node binary, or container runtime.

These commands verify byte lengths and SHA-256 digests. They do not decode a
block, check its claimed block hash or height, verify ancestry or checkpoints,
or establish consensus validity. Reports always keep `blockDecodingVerified`,
`consensusVerified`, and `launchReady` false, with `qualification: pending`.

## Import and recheck

Prepare a [candidate consensus manifest](chain-manifest.md) and raw binary files
from a separately prepared chain. The importer does not generate a chain. Name
the files by height, using ten decimal digits and `.bin`:

```text
raw-blocks/
  0000000000.bin    # genesis
  0000000001.bin    # first seed block, if declared
  0000000002.bin    # next seed block, if declared
```

Use raw serialized bytes, not hexadecimal text. Each file must match the
manifest's declared `bytesLength` and `bytesSha256`. Seed blocks must form the
contiguous history declared by the manifest. The importer reads only the declared
files; unrelated source files are not included.

```sh
zdn chain import --manifest candidate-chain.json \
  --blocks-dir raw-blocks --output candidate-chain.tar

zdn chain verify --manifest candidate-chain.json \
  --bundle candidate-chain.tar
```

The output parent directory must exist. Import uses a temporary file in that
directory, verifies the completed bundle, then publishes it without replacing an
existing path. An existing file, directory, or symlink is refused. Ordinary
pre-publication failures remove the temporary file and leave no output bundle.
If publication succeeds but a later filesystem durability check fails, inspect
the existing output with `chain verify` before retrying with a new name.

Keep the bundle and its expected manifest together. Verification reads the saved
bytes again and requires the expected manifest's normalized fingerprint. It does
not need the original raw files. A valid bundle for a different expected chain is
rejected. Labels and source/output paths do not enter the consensus fingerprint.

## Format and limits

The bundle is an uncompressed deterministic TAR with one `bundle.json` entry,
then `blocks/0000000000.bin` and the declared seed blocks in height order.
Metadata contains the normalized manifest, its fingerprint, and format version
`zdn-chain-bundle/v1alpha1`. Headers, padding, and end markers have one encoding.
Repacking the archive can change that encoding and make verification fail.

Verification checks the complete file, including metadata, entry order, byte
digests, padding, and end markers. It rejects missing, extra, duplicate, linked,
or renamed entries and appended data. It never extracts archive paths. Source
blocks and bundle inputs must be regular files; symlinks and special files are
refused.

Limits are 2 MiB for the serialized normalized manifest, 4,096 blocks including
genesis, 128 MiB of raw block data, and 256 MiB for the bundle. Each block must
also satisfy the manifest's 2,000,000-byte maximum. These are import limits, not
node consensus rules or measured capacity recommendations.

The JSON report contains the consensus fingerprint, complete bundle SHA-256 and
length, block count, raw byte count, and `byteIntegrityVerified: true`.
Verification results are computed from the current bytes. No stored status flag
or report can authorize launch or substitute for qualification evidence.

## Node loading and remaining work

[Bootstrap and readiness](bootstrap-readiness.md) now compare node-decoded
identities and effective rules and load a supported history through the verifier.
The first recipe requires a checkpoint at every saved height. Checkpoint acceptance
is distinct from full semantic validation. Run loading on each node before block
production; custom Testnet does not self-seed genesis.

A [network configuration renderer](node-config.md) now maps supported manifest
choices to candidate Zakura TOML and rejects settings the inspected interface
cannot express. A [runtime renderer](runtime-config.md) adds per-node settings
and startup arguments. The [private deployment lifecycle](private-devnet.md)
launches the runtime, but
[chain and client qualification](compatibility.md) remains pending. This byte
bundle does not establish a supported release or payment path.
