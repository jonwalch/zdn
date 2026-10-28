# Candidate Zakura runtime configuration

`chain render-runtime` adds per-node runtime settings to the
[network configuration](node-config.md). It prints the complete candidate TOML,
its SHA-256, the consensus fingerprint, container paths, and startup arguments.
It runs offline and starts no process.

```sh
zdn chain render-runtime --manifest candidate-chain.json \
  --deployment-id DEPLOYMENT_UUID_FROM_BINDING --node-id node-0 \
  --listen-addr 10.0.1.5:18233 --peer 10.0.1.6:18233 \
  --output node-0.toml
```

Use the full version-4 deployment UUID from the network binding. Keep the node ID
stable across updates. IDs accept 1 to 63 lowercase letters, digits, or hyphens,
with a letter or digit at each end. The renderer checks their syntax; it does not
read the binding store or verify resource ownership.

The default role is `follower`. To prepare a producer, add
`--role producer --reward-address YOUR_TESTNET_TRANSPARENT_ADDRESS`.
The producer requires disabled proof of work and an explicit, checksum-valid
Testnet P2PKH or P2SH reward address. A follower rejects reward settings.
Address validation does not prove ownership or that rewards can fund Ironwood
payments. The funding backend and that conversion path still need qualification.

`--output` saves the TOML to a new local file. Existing files, directories, and
symlinks are preserved. Its parent must exist. The same create-only publication
and post-publication durability limits as [network rendering](node-config.md)
apply. Without `--output`, only JSON is printed.

## Paths and startup record

The default container data root is `/var/lib/zdn`. Override it with `--data-root`
using a canonical absolute Linux path. Relative paths, `/`, empty components,
dot segments, whitespace, and shell syntax are rejected. The maximum root is
512 bytes, with at most 255 bytes per component.

Every node uses this namespace:

```text
DATA_ROOT/deployments/DEPLOYMENT_UUID/nodes/NODE_ID/chains/FULL_FINGERPRINT/
  zakura.toml
  state/
  identity/
  rpc/.cookie
```

The node creates the cookie when it starts. Rendering produces no credential and
creates none of these directories. Cookie and native P2P identity paths stay
outside the state subtree so state snapshots need not copy those secrets.
Zakura adds its own database-format and network subdirectories under `state/`.
The renderer pins the node's network name to `zdn_` plus 16 fingerprint characters;
an arbitrary label must not redirect those database subdirectories.

RPC/peer/reward changes preserve these paths. Another deployment UUID, node ID,
or consensus fingerprint selects a different namespace. This is path isolation
only. The [host lifecycle](host-lifecycle.md) checks mount ownership, symlinks,
and saved state identity. Storage-format compatibility still requires review
before image updates or backup reuse; identity checks do not establish it.
Changed consensus rules require a new devnet in the deployment workflow.

`startupArgv` contains an argument array for the inspected image's binary:
`/usr/local/bin/zakurad`, `--config`, the container config path, and `start`.
`requiredEnvironmentRemovalPrefixes` lists `ZAKURA_`, `ZEBRA_`, and `OTEL_`.
The first two can override TOML; the last can enable trace export. The host
launcher removes inherited variables, creates private writable directories,
and installs the exact config. The renderer report does none of that work.
The local `--output` path is independent of the container path.

## Runtime policy

- State is persistent and uses archive storage. Non-finalized state backups stay
  enabled. Automatic deletion of older databases is disabled.
- RPC defaults to `127.0.0.1:18232` and requires the node-generated cookie.
  `--rpc-listen-addr` accepts a numeric loopback address and nonzero port, and
  must differ from the P2P listener. Indexer, admin, metrics, health, and tracing
  control listeners remain absent under the inspected defaults.
- Producer configuration sets the reward address. Both roles leave the internal
  miner and optimistic block inventory disabled. The separate
  [block controller](block-producer.md) defaults to 25 seconds. A role is not
  an access boundary: authenticated RPC exposes
  the node's full method set.
- Checkpoint sync stays enabled with the declared checkpoint list. VCT fast sync
  is explicitly disabled. This does not expand checkpoint trust or replace
  artifact validation.
- For this private development profile, `mempool.debug_enable_at_height` is the
  highest declared seed or checkpoint height, or zero for genesis-only inputs.
  It allows an idle chain to use its mempool after an actual stored tip reaches
  that height. It does not prove the tip belongs to the expected chain or bypass
  transaction/proof validation. `rpc.debug_force_finished_sync` stays false.
- Public seed lists and the peer cache stay disabled as in the network renderer.
  The candidate transport remains legacy P2P. Firewall and membership control,
  Docker limits, image selection, and service supervision remain deployment work.

## Validation and source contract

The report uses `zdn-zakura-runtime/v1alpha1` and adapter
`zakura-runtime-toml/v1alpha1`. It always keeps `nodeConfigValidated: false`,
`qualification: pending`, and `launchReady: false`. It does not read saved block
bytes or invoke Zakura's parser.

The mapping follows research commit
`860203d4d39a480c145f9c04bdf0d1dd08ab0625`. Sources are `zakurad/src/config.rs`,
its mempool/metrics/health/tracing/compatibility config types,
`zakura-state/src/config.rs`, `zakura-network/src/config.rs`,
`zakura-consensus/src/config.rs`, and `zakura-rpc/src/config/{rpc,mining}.rs`
under `node/zakura/crates/`. Startup arguments follow
`zakurad/src/commands/entry_point.rs`; the executable path follows
`node/zakura/docker/Dockerfile`.
These paths and the research commit are historical attribution, not a requirement
for access to the research repository. Inspect the node source archive and source
map supplied with the [public release](https://github.com/jonwalch/zdn/releases),
using the [source setup guide](preview-start.md#1-select-and-verify-a-profile).
Keep the public source commit, snapshot digest and historical origin identities
separate; a source map does not make their hashes interchangeable.

Run `cargo test --locked --test runtime_config --test runtime_cli` for the focused
checks. They use independent TOML structures, synthetic address vectors, and
temporary local files. [Bootstrap and readiness](bootstrap-readiness.md) provide
saved-history loading and effective-rule checks for an existing node. Rendering
still does not invoke the node parser or establish launch/client qualification.
