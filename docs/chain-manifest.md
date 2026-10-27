# Candidate consensus manifests

The chain contract includes a versioned consensus specification, deterministic fingerprint,
and [saved-byte import and verification](chain-artifacts.md). A
[network configuration renderer](node-config.md) maps supported choices to
candidate Zakura TOML. These are offline contracts; they do not establish node
acceptance or consensus validity. The [host lifecycle](host-lifecycle.md) executes
the runtime, but chain-recipe and client qualification remain pending. The
[runtime renderer](runtime-config.md) now adds per-node settings and startup arguments.

Inspect a candidate JSON file:

```sh
zdn chain inspect --manifest candidate-chain.json
```

The command reads a regular file of at most 2 MiB. It prints normalized rules and
`consensusFingerprint`, with `structurallyValid: true`, `qualification: pending`,
and `launchReady: false`. Invalid inputs fail without printing an identity.
Inspection makes no files, starts no tools, and needs no AWS credentials.

`plan` emits a draft `ChainRequest`, not a launch manifest. Its request hash and
compatibility record are separate from the consensus fingerprint. The draft
does not supply genesis or resolved node parameters.

## Identity and encoding

The manifest uses `apiVersion: zdn-consensus/v1alpha1` and
`ruleset: zakura-configured-testnet/v1`. The ruleset identifies the interpretation
of these parameters and the fixed node rules inspected for this contract. It is
not a binary version or proof that arbitrary builds implement those rules.

The fingerprint is lowercase SHA-256 over the ASCII prefix
`zdn-consensus/v1alpha1`, one NUL byte, and the normalized compact JSON object.
JSON object keys are sorted recursively. There is no whitespace or trailing
newline. Consensus numbers are integers. Hexadecimal identities use lowercase.
Normalization resolves the defined optional defaults before encoding. Unknown
fields and unsupported contract versions are rejected.

Defaults belong to this manifest schema, not to Zakura's TOML parser. Missing
seed blocks and funding streams resolve to empty lists; an empty checkpoint
list resolves to the genesis checkpoint. Unshielded coinbase spending defaults
to false. Missing optional NU7, Orchard-disabling, and SLH settings mean those
rules are not scheduled; a missing initial NSM balance means derive it from
chain state, which differs from an explicit zero. Lockbox disbursements must be
explicit and nonempty for the required NU6.1 schedule.

The network renderer writes these resolved choices explicitly. Omitting raw
node fields can inherit different public-Testnet defaults. The renderer rejects
choices absent from the inspected custom-Testnet TOML interface: no temporary
Orchard rule, unshielded coinbase spending, and experimental SLH.

The specification binds these inputs:

| Input | Purpose |
| --- | --- |
| Network kind and magic | Identify the isolated custom Testnet and its P2P message namespace. |
| Genesis, seed blocks, and checkpoints | Bind block identities, exact byte digests and lengths where supplied, and the initial history. Locations are separate. |
| Full upgrade schedule | Record the effective activation heights, including an explicit inactive future upgrade. |
| Subsidy and monetary settings | Bind slow start, halving, complete funding streams, lockbox disbursements, initial NSM balance, and coinbase spend policy. |
| Difficulty and validation settings | Bind the canonical compact difficulty limit, PoW mode, maximum block-time rule activation, and temporary Orchard disabling height. |
| Optional experimental SLH rules | Record the explicitly requested future contract, activation, and limits. This does not establish node or wallet support. |

Labels, deployment UUIDs, topology, peers, ports, paths, instance sizes, API
visibility, controller cadence, and build/client versions are not consensus
fields. Keep them in the deployment and qualification records. A compatible
binary update or a change to the 25-second controller target does not by itself
change this fingerprint.

Funding and lockbox receivers use P2SH script hashes, avoiding multiple address
spellings for the same output script. The renderer encodes Testnet P2SH addresses.
The selected node must still validate the complete recipe.

## Validation boundary

Structural checks cannot establish that supplied block bytes exist, match their
hashes, or pass node consensus. They also cannot prove that funding inventory can
be spent, that a node reports the same effective rules, or that a wallet and
lightwalletd support the chain. The optional SLH record remains a pending profile;
the inspected node configuration does not provide that custom-Testnet capability.

`chain import` saves declared genesis/seed bytes and checks their lengths and
SHA-256 digests. `chain verify` rechecks the bundle against an expected manifest.
Neither command checks decoded block identities or consensus. The separate
[bootstrap and readiness commands](bootstrap-readiness.md) use node-owned
diagnostics and actual best-chain observations. [Automatic runtime deployment](private-devnet.md)
uses these checks without establishing client compatibility qualification.
Database and backup reuse must check the approved fingerprint and storage-format
compatibility. Complete chain and payment acceptance still requires the
[qualification procedure](compatibility.md).

## Source mapping and fast checks

The schema follows the pinned research implementation at
`jonwalch/zcash-transparent-pq` commit `860203d4d39a480c145f9c04bdf0d1dd08ab0625`.
No node or cryptographic implementation is imported into the CLI.

| Reference | Use in this contract |
| --- | --- |
| [Custom Testnet configuration](https://github.com/jonwalch/zcash-transparent-pq/blob/860203d4d39a480c145f9c04bdf0d1dd08ab0625/node/zakura/crates/zakura-network/src/config.rs) | Map the candidate node's configuration fields and distinguish custom Testnet from Regtest. |
| [Testnet parameter builder](https://github.com/jonwalch/zcash-transparent-pq/blob/860203d4d39a480c145f9c04bdf0d1dd08ab0625/node/zakura/crates/zakura-chain/src/parameters/network/testnet.rs) | Identify effective parameters and inherited defaults that a complete manifest must resolve explicitly. |
| [Local genesis generator](https://github.com/jonwalch/zcash-transparent-pq/blob/860203d4d39a480c145f9c04bdf0d1dd08ab0625/node/zakura/crates/zakura-chain/src/local_genesis.rs) | Establish that generated bytes, magic, and seed history must be saved once. Manifest inspection does not run the generator. |
| [Compact difficulty encoding](https://github.com/jonwalch/zcash-transparent-pq/blob/860203d4d39a480c145f9c04bdf0d1dd08ab0625/node/zakura/crates/zakura-chain/src/work/difficulty.rs) | Reject noncanonical, signed, zero, or overflowing compact representations without evaluating block work. |

Run `cargo test --locked --test chain_manifest --test chain_cli` for the focused
checks. The [synthetic vector](../tests/fixtures/chain-manifest/README.md) has an
independent reference originally generated with Python's SHA-256 and now
reproduced byte-for-byte by test-only Rust with `ring`, not production's `sha2`.
Run `cargo test --locked --test reference_vectors` to check that reference.
It is not a launch example or real chain.
