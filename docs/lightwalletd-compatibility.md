# lightwalletd compatibility candidate

Upstream **lightwalletd v0.5.5** has the protocol fields
and parser needed for Ironwood. Use it as the compatibility candidate. This source review
and its fixture tests do not qualify the custom Testnet, a wallet, or payments.
The [chain and payment procedure](compatibility.md) remains open.

Automatic deployment now integrates the [cookie supervisor](lightwallet.md).
lightwalletd reads static credentials at startup. Mounting the cookie file alone
does not make authentication work after a node restart.

## Exact inputs

| Component | Checked source |
| --- | --- |
| lightwalletd | [`v0.5.5`, `d16d48124e9ad4157ebc2324b5090c6ba201470c`](https://github.com/zcash/lightwalletd/tree/d16d48124e9ad4157ebc2324b5090c6ba201470c) |
| Canonical light-wallet protocol | [`v0.5.0`, `ac7cee052a1bf5d430985a478d39e8b513fc4bd4`](https://github.com/zcash/lightwallet-protocol/tree/ac7cee052a1bf5d430985a478d39e8b513fc4bd4) |
| Candidate Zakura source | Research repository revision [`91381abfa57563653427d4a7341f2fce14d82b90`](https://github.com/jonwalch/zcash-transparent-pq/tree/91381abfa57563653427d4a7341f2fce14d82b90/node/zakura) |

The two protocol
files bundled by lightwalletd are byte-identical to the canonical v0.5.0 files:

| File | SHA-256 |
| --- | --- |
| `walletrpc/service.proto` | `6fbfa974081fb02366a3118a25764af289bdbb86688978f5ff2bae661dfa346a` |
| `walletrpc/compact_formats.proto` | `d8d0c8aaa5ceec7d5dcc188ef25b04011df2ec0254901620fce982fc13aeb32d` |

The older protocol copy in Zakura's test support lacks the Ironwood fields. Use
the canonical candidate protocol for the new adapter. Both upstream projects use
the MIT license. Retain the upstream copyright and license when copying their
definitions. No node implementation or wallet dependency is imported by this
source review.

## Protocol support found in source

| Need | Candidate behavior | Remaining check |
| --- | --- | --- |
| Read v6 transactions | The parser implements ZIP 229, version group `0xd884b698`, with separate Orchard and Ironwood bundles. | Parse actual accepted transactions from the selected node. |
| Scan Ironwood compact blocks | `CompactTx.ironwoodActions` is field 9. `ChainMetadata.ironwoodCommitmentTreeSize` is field 3. Pool filtering includes Ironwood. | Compare real actions, txids, and tree sizes with the same node block. |
| Obtain Ironwood tree state | `TreeState.ironwoodTree` is field 7. The server copies `z_gettreestate`'s Ironwood final state. | Decode the tree with the selected wallet and build witnesses. |
| Obtain subtree roots | `ShieldedProtocol.ironwood` is value 2. The server requests `z_getsubtreesbyindex` with `"ironwood"`. | Check the selected wallet's subtree use and recovery. |
| Submit transactions | `SendTransaction` forwards the serialized bytes to `sendrawtransaction`. Node validation determines acceptance. | Submit a valid Ironwood payment, confirm it, scan it, and spend it again. |

Sources: [v6 parser](https://github.com/zcash/lightwalletd/blob/d16d48124e9ad4157ebc2324b5090c6ba201470c/parser/transaction.go),
[compact fields](https://github.com/zcash/lightwallet-protocol/blob/ac7cee052a1bf5d430985a478d39e8b513fc4bd4/walletrpc/compact_formats.proto),
[service protocol](https://github.com/zcash/lightwallet-protocol/blob/ac7cee052a1bf5d430985a478d39e8b513fc4bd4/walletrpc/service.proto),
and [server methods](https://github.com/zcash/lightwalletd/blob/d16d48124e9ad4157ebc2324b5090c6ba201470c/frontend/service.go).

Zakura provides `getblock` raw bytes and verbose transaction IDs, Ironwood tree
sizes, `z_gettreestate`, `z_getsubtreesbyindex`, and `sendrawtransaction` in the
checked [RPC implementation](https://github.com/jonwalch/zcash-transparent-pq/blob/91381abfa57563653427d4a7341f2fce14d82b90/node/zakura/crates/zakura-rpc/src/methods.rs).
lightwalletd obtains transaction IDs from verbose `getblock`, then requests raw
bytes by that block hash. This keeps both replies on one block across a reorg.
The node, not the indexer, remains the consensus verifier.

## Custom-chain readiness

The server recognizes a `/Zakura:` backend and uses the node's activation data.
Its cache starts at height 0. It does not require public Testnet's Sapling height.
These are [startup behaviors](https://github.com/zcash/lightwalletd/blob/d16d48124e9ad4157ebc2324b5090c6ba201470c/cmd/root.go),
not evidence that the selected custom-chain recipe works with a wallet.

Zakura reports `test` for custom Testnet, public Testnet, and Regtest. That label
does not identify this devnet. Bind readiness to the trusted consensus
fingerprint and exact genesis/checkpoint hashes. Keep each devnet's cache in its
own directory; lightwalletd's internal cache path uses the shared chain label.

`GetLightdInfo` advertises protocol `v0.5.0` and reports node height and branch ID.
`GetLatestBlock` also reads the node. Neither proves that compact data can be
served. Read a bounded block range, check contiguous hashes and exact checkpoint
identity, then compare its tree sizes and `GetTreeState` with trusted node data.
Use deadlines and reject incomplete streams. See the
[block fetch and metadata implementation](https://github.com/zcash/lightwalletd/blob/d16d48124e9ad4157ebc2324b5090c6ba201470c/common/common.go).

Use `GetBlockRange` for genesis: this server rejects height 0 in `GetBlock` as an
unspecified identifier and does not implement `GetBlock` by hash. For
`GetTreeState`, a positive height avoids its special height-0 hash path. That
hash path takes 32 bytes in display order; compact block hashes use canonical
little-endian bytes. Tree state also requires a nonempty Sapling final state, so
use a checkpoint at or after Sapling activation.

An empty Ironwood tree proves no incoming-payment scan. Readiness must report
its limited observations and leave payment qualification pending.

## Authentication and service lifecycle

The candidate reads `.conf` keys `rpcbind`, `rpcport`, `rpcuser`, and
`rpcpassword`; the password must be nonempty. Its HTTP client captures those
credentials and sends Basic authentication on each request. It does not reread
the node cookie. The upstream unauthenticated-node example is unsuitable for
zdn's existing authenticated node service. See the
[configuration reader](https://github.com/zcash/lightwalletd/blob/d16d48124e9ad4157ebc2324b5090c6ba201470c/frontend/rpc_client.go)
and [HTTP client](https://github.com/zcash/lightwalletd/blob/d16d48124e9ad4157ebc2324b5090c6ba201470c/frontend/rawrequest.go).

The service adapter must keep node authentication enabled. It must provide a
private generated configuration from the current cookie and restart lightwalletd
when that cookie changes, or provide an authenticated local bridge. Keep secrets
out of arguments, receipts, logs, and image layers. Test missing cookies, atomic
replacement, stale credentials, node restart, and host reboot before enabling
automatic installation.

The supported process flags include `--grpc-bind-addr`, `--http-bind-addr`,
`--zcash-conf-path`, `--data-dir`, and `--log-file`. The private host design uses
loopback for gRPC and HTTP. Plaintext gRPC must stay within that host and its
authorized SSM tunnel. Startup can wait through multiple backend retries; the
zdn operation still needs its own bounded deadline. Pin the image, enforce a
non-root UID, bound resource use, and give the cache a separate persistent path.

## Container metadata

The [release workflow](https://github.com/zcash/lightwalletd/blob/d16d48124e9ad4157ebc2324b5090c6ba201470c/.github/workflows/CI.yaml)
publishes `electriccoinco/lightwalletd` and mirrors it to `zodlinc/lightwalletd`.
Registry metadata for `electriccoinco/lightwalletd:v0.5.5` was checked without
downloading or executing image layers:

| Item | Digest or value |
| --- | --- |
| Tag's image index | `sha256:483a361483531f9fa7b13c67ca69d69e394179ea31746cc0022fbe3af65ab5e0` |
| Linux x86-64 manifest | `sha256:729f5fee89c2cac232d9b6e8006680c2b8e3755a94fe9069dc0e10f5a98122e9` |
| Image configuration | `sha256:eb7349ee93d31be4f6c6873c3a020ee8c5401f3be758ea2a7141976f0d31a444` |
| Entrypoint | `lightwalletd` |
| Working directory | `/srv/lightwalletd` |
| Configured user | Unset; deployment must enforce a non-root user. |

This is a candidate artifact identity. Source-to-image provenance, binary
version, host execution, and compatibility have not been verified. Do not turn
this registry observation into a qualified release entry.

The deployment input uses `zdn-lightwallet-image/v1alpha1`. Save an image record,
the exact single-platform manifest bytes, and the exact image configuration
bytes. The record declares the source and protocol revisions above, Linux
`amd64`, `/usr/local/bin/lightwalletd`, and `/usr/bin/env`. It pins both the child
manifest and configuration by SHA-256. An image index or mutable tag is not an
accepted deployment input. The deployment repository must be inside the chosen
team's same-account, same-region `zdn/TEAM/` ECR namespace.

`zdn lightwallet verify-image --record IMAGE.json --manifest MANIFEST.json
--config CONFIG.json` checks those saved bytes and the candidate's runtime
metadata. It rejects inherited environment variables other than the supported
`PATH`, image-declared volumes, and build triggers. The service replaces the
entrypoint with the clean-environment launcher, enforces UID 10001, and supplies
its own arguments and resource limits. Before starting it, the host repeats the
check with `--docker-inspect INSPECT.json`, using a fresh inspection from its
trusted Docker daemon. A supplied JSON file alone is not proof of a host pull.

The report separates declared source and protocol revisions from verified
artifact bytes and observed Docker metadata. It keeps source provenance,
binary contents, launch readiness, and payment qualification unverified. Labels
cannot promote any of those claims. Fixture tests cover byte substitution,
cross-record evidence reuse, namespace confusion, unsupported platforms and
startup defaults, and forged qualification labels. Real startup, cache
retention, cookie rotation, restart recovery, and Ironwood payments still need
the live checks below.

## Remaining live checks

The next live check must use the selected custom Testnet with a pinned node,
image, wallet, and funding recipe. It must prove authenticated startup and cookie
rotation, actual Ironwood compact/tree data, payment submission, scanning, later
spending, and restart/reorg recovery. Node-only checks do not
satisfy these checks. Keep launch readiness and payment qualification false
until that evidence exists.
