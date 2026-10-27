# Candidate Zakura network configuration

`chain render-config` converts a [consensus manifest](chain-manifest.md) to a
candidate Zakura network TOML fragment. It runs offline and does not start a
node, read a saved block bundle, or call AWS.

```sh
zdn chain render-config --manifest candidate-chain.json \
  --listen-addr 10.0.1.5:18233 \
  --peer 10.0.1.6:18233 --peer 10.0.1.7:18233 \
  --output zakura-network.toml
```

Without `--output`, the command only prints JSON. The report includes the TOML,
its exact SHA-256, and the consensus fingerprint. It always reports
`scope: network`, `nodeConfigValidated: false`, `qualification: pending`, and
`launchReady: false`. The report versions are `zdn-zakura-config/v1alpha1` and
adapter `zakura-network-toml/v1alpha1`.

The output parent directory must exist. The command stages the complete TOML
and publishes it without replacing an existing file, directory, or symlink.
Concurrent writers cannot overwrite the winner. A filesystem durability error
after publication can leave the complete output present; inspect that file
before retrying with a new name. Existing directory permissions stay unchanged.

## Network options

The default listener is `127.0.0.1:18233`. Set an explicit interface address for
each future host. Listener and peer inputs must contain numeric IPv4 or IPv6
addresses and nonzero ports. Put IPv6 addresses in brackets, such as
`[::1]:18233`. DNS names, wildcard addresses, multicast, the IPv4 limited-broadcast
address (`255.255.255.255`), and IPv6 scope IDs are rejected. IPv4-mapped IPv6
addresses normalize to IPv4.

There are no default peers. Repeat `--peer` to select up to 128 endpoints. The
renderer sorts and deduplicates them. It sets both public seed lists explicitly,
disables the peer cache, selects the legacy P2P stack, and clears native Zakura
bootstrap peers. This is a candidate transport choice for this adapter. Runtime
peer behavior and transport compatibility remain unqualified. An explicit peer
can advertise other peers; firewall and membership controls still belong to the
deployment.

The default network name is `zdn_` followed by the first 16 characters of the
consensus fingerprint. `--network-name` accepts 1 to 30 ASCII letters, digits,
or underscores. Zakura's reserved names are rejected without regard to case.
The name is a node label. Deployment UUIDs still identify separate devnets.

Names, listeners, and peers do not change the consensus fingerprint. They do
change the configuration hash. Equivalent normalized inputs produce the same
TOML and hash.

## Manifest mapping

The fragment uses `[network.network]` for a configured Testnet. It writes the
network magic, genesis hash, explicit upgrade schedule, difficulty limit, PoW
mode, subsidy parameters, funding streams, lockbox outputs, checkpoints, and
temporary Orchard rule. Empty funding streams stay explicitly empty. Address
extension is disabled. A missing initial NSM balance stays omitted; an explicit
zero stays zero. Funding address order and repeated lockbox outputs are preserved.

The adapter rejects these manifest choices because the inspected custom-Testnet
TOML interface cannot express them:

- No temporary Orchard disabling rule.
- Unshielded coinbase spending enabled.
- Experimental SLH settings.

Both disabled PoW and Equihash can be rendered. This does not establish that
`generate(1)` works for both. The scheduled-block path requires the
selected node's PoW-disabled mode.

The JSON input is limited to 2 MiB. The renderer also bounds the serialized input
and normalized manifest to 2 MiB, and the output TOML to 8 MiB. These are CLI
resource limits. They do not establish node capacity.

## Source mapping and checks

The adapter follows research commit
`860203d4d39a480c145f9c04bdf0d1dd08ab0625`; it imports no node code or dependencies.

| Source under `node/zakura/crates/` | Adapter use |
| --- | --- |
| `zakura-network/src/config.rs`, `src/config/tests/vectors.rs` | Custom Testnet TOML fields, explicit seed/cache options, checkpoint tuple format. |
| `zakura-chain/src/parameters/network/testnet.rs` | Upgrade, funding, lockbox, default, and network-name contracts. |
| `zakura-chain/src/block/hash.rs` | Checkpoints use internal little-endian byte arrays; genesis uses display hex. |
| `zakura-chain/src/work/difficulty.rs` | Expand validated compact targets to `0x` plus 64 hexadecimal digits for the node's U256 parser. |
| `zakura-chain/src/transparent/address.rs` | Encode Testnet P2SH addresses with prefix `1cba` and Base58Check. |
| `zakura-network/src/zakura/handler.rs` | Native bootstrap defaults that must also be cleared. |

Run `cargo test --locked --test node_config --test node_config_cli` for the focused
tests. Tests independently inspect TOML fields and include fixed Python-derived
difficulty/address vectors, asymmetric checkpoint hashes, option errors, and
concurrent output publication. `cargo test --locked --test reference_vectors`
reproduces the original vectors with test-only byte-array arithmetic and `ring`,
without the production codecs. To explicitly regenerate the reference files, run
`cargo test --locked --test reference_vectors regenerate -- --ignored`.
These checks do not invoke a node parser.

## Renderer and lifecycle boundaries

Use the [runtime renderer](runtime-config.md) to add per-node state directories,
RPC authentication, mining settings, and startup arguments. The renderer alone
does not launch or validate a node. The [host lifecycle](host-lifecycle.md)
implements launch and container limits; [bootstrap](bootstrap-readiness.md)
loads supported saved history through the node verifier. Custom
Testnet does not seed its own genesis on startup in the inspected node.

The selected node must decode and validate the [saved history](chain-artifacts.md),
accept the complete configuration, and report effective rules that match the
manifest. Funding-period rules and monetary arithmetic remain node checks.
Then bind the complete launch record and qualify the node, wallet, and
lightwalletd together through [chain and client qualification](compatibility.md).
