# Wallet payments and recovery

**ZDN CLI payments use a separate Ironwood wallet program; Vizor and Zodl
have not yet been tested with ZDN.** These are disposable-network test coins,
not public Testnet or Mainnet funds. A ready RPC service alone does not establish
wallet compatibility.

## Choose your task

- **Make your first payment:** follow [Alice and Bob](#first-payment-alice-and-bob),
  starting with the platform and wallet-program prerequisites. It covers local
  wallet creation, reward maturity, payment confirmation and cleanup.
- **Use transparent payments:** see [transparent sending and receiving](#transparent-sending-and-receiving).
  This requires a matching new backend; existing released wallet binaries may
  not advertise the required capabilities.
- **Resume an interrupted payment:** keep the store and original operation ID;
  follow [interruption recovery](#if-interrupted-when-finished). Do not pay again
  with a new operation ID.
- **Use an existing wallet:** see [named wallets](#named-wallets),
  [sync and checkpoint recovery](#explicit-resumable-sync-and-checkpoint-recovery-statev2),
  or [payment status and recovery](#durable-funding-payments-and-status).
- **Inspect interfaces or maintain storage:** use the
  [advanced reference](#advanced-reference-backend-storage-and-recovery) below
  the walkthrough. Bare-key imports are scan-only, not a signing-recovery path.

This is an experimental trusted-node wallet, not a generally qualified wallet or
consensus light client. Keep plaintext keys and complete recovery backups private.

## First payment: Alice and Bob

This walkthrough uses the CLI's private full-node connection, **not lightwalletd
or a GUI app**. All three wallets stay on this computer. Alice and Bob have
independent keys, not separate people or machines in this example. ZDN transports
public chain data and signed transactions; the separately trusted wallet program
receives local key paths and signs locally. Never upload wallet keys to AWS,
send them through chat, or put them in the node source, a Git checkout or a build
archive. The wallet program is not sandboxed; only run bytes you trust.

### 1. Obtain the matching wallet program

**Preview 3 on Mac: install the controller and wallet from source** using the
[free manual or source-building Homebrew path](install-source.md), then continue
below with your physical wallet path and its reviewed local-build hash. Preview 3
does not provide Mac executable downloads.

The withdrawn Preview 2 Mac downloads were rejected by Gatekeeper on arm64
macOS 27.0.1; they were not Developer ID signed or notarized. Do not remove
quarantine, re-sign downloaded files, disable Gatekeeper or otherwise bypass OS
protections. If a locally built program is blocked, stop and investigate.
Source installation does not qualify those historical browser binaries.

Network-management downloads do not by themselves include a usable wallet.
Select the payment profile in the [public preview release](https://github.com/jonwalch/zdn/releases)
for the separate wallet executable, matching source and required notices, or
build its exact supplied source. The management-only profile does not require
these optional files. Do not use an arbitrary executable called `ironwood-wallet`.

The public release supplies standalone corresponding wallet source, originally
developed in `jonwalch/zcash-transparent-pq` as `experiments/ironwood-wallet`.
No access to that repository is required. Its crate version is `0.1.0`, which
is **not a sufficient version pin**; it has no `--version` interface. Reference
source revision is `70ccc7f45ef9ecdea46151719b82b356b48e2d76`.
Keep its README, Cargo.lock and upstream MIT/Apache-2.0 attribution.
Its exact `zakura-*` dependencies are Common 3.0.0 (authoritative
Common source `0b13ab9e66ea8855a7b4305b17e44fdccbeb3d58`), not arbitrary newer
wallet libraries. This source reference is not a publisher-signed binary release.

For a reviewed source build, follow [source installation](install-source.md) for
the exact archive checksum, wrapper/subtree extraction layout, Rust/Cargo 1.97.1
manual commands and the source-building Homebrew alternative. Native C/linker
tools compile bundled SQLite. Homebrew backend selection must use the physical
versioned Cellar executable, not its `bin` or `opt` symlink.

Do not substitute a node build or run proof-generation examples to install it.
Record the source revision, lockfile hash, toolchain, executable hash and notices.
For a downloaded binary, require the provider's matching source/notices and
independently verified hash instead. Locally hashing an untrusted download does
not make it trusted. macOS signing/notarization and a user's OS trust decision
are separate; do not disable Gatekeeper or remove quarantine to follow this guide.

Set `IW` to the absolute regular-file executable path and `IW_SHA256` to its
verified 64-hex executable hash. Before storing that pair, check the public
capability response:

```sh
"$IW" capabilities
```

Require schema 1 and `ironwood-wallet-state/v2`,
`ironwood-wallet-state-observation/v2`, and
`ironwood-wallet-snapshot-payment/v2`. These capabilities and an executable hash
are interface/trust inputs, not proof that payments work on a particular node.
The matching chain uses public Testnet genesis
`05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38`,
all pre-NU7 upgrades through NU6.3 at height 1 and no NU7. Use the reviewed
manifest, saved block bundle and node source from the same selected combination;
stock Testnet, Regtest and other activation schedules are not substitutes.

### 2. Create the local reward wallet before launch

Complete [account/team setup and launch inputs](../README.md#requirements-and-build)
first. Use its default saved profile `devnet`, `devnet.yaml`, default state and
wallet directories throughout this example. Keep state outside captured source.
For a fresh one-node configuration, the source form is:

```sh
zdn init --name demo --source "$NODE_SOURCE" --revision "$NODE_REV" --nodes 1 \
  --dockerfile node/zakura/docker/Dockerfile --build-context .
zdn devnet render
zdn identity bind --manifest "$CHAIN_MANIFEST"
```

Use the distributed public node-source Git root for `NODE_SOURCE` and its exact
verified revision for `NODE_REV`. That archive preserves the
`node/zakura/docker/Dockerfile` path and uses its Git root (`.`) as build context;
it does not require a private research checkout. A separately reviewed standalone
Zakura source tree may instead use `docker/Dockerfile`; select the recipe for
the source you actually have, not a guessed path or another revision.
Require `render` success and review the captured build contract before binding;
it makes no AWS calls or build and is not live qualification. Do not change the
recipe after launch has saved immutable inputs to bypass an earlier failure.

Do not overwrite an existing configuration. Inspect it with `zdn check` and use
the same config/profile for launch. Set `NETWORK` to the exact `network_id` UUID
printed by `identity bind`; do not invent a new ID. Binding infers the scope from
the saved profile and registers the reviewed manifest for local wallet creation.
The UUID works before deployment; `demo` is the label from the configuration.

```sh
umask 077
zdn wallet backend set --backend "$IW" --backend-sha256 "$IW_SHA256"
zdn wallet create "$NETWORK" --name funding
zdn wallet create "$NETWORK" --name alice
zdn wallet create "$NETWORK" --name bob
```

Each `create` asks the backend for fresh random keys and prints a public receipt.
Check all three have `scan_only: false`, the same network UUID, and different
`public.ironwood_address_hex` values. Keep the receipt's funding
`public.reward_address` as `REWARD_ADDRESS`; it is public, not the key. Do **not**
use `key-import` or `wallet import` here: imports are scan-only and cannot spend.
An incomplete create is not safe to overwrite; preserve it and investigate.

Launch exactly that network with the funding address, using the other reviewed
[launch inputs](../README.md#keep-the-original-inputs-and-private-state):

```sh
zdn up --manifest "$CHAIN_MANIFEST" --bundle "$CHAIN_BUNDLE" \
  --host-helper "$HOST_HELPER" --ami-id "$AMI_ID" \
  --availability-zone "$ZONE" --reward-address "$REWARD_ADDRESS" --yes
zdn devnet health demo
zdn wallet show demo --wallet funding
zdn wallet show demo --wallet alice
zdn wallet show demo --wallet bob
```

Launch creates billed AWS resources. It does not give a new wallet authority over
rewards paid to an old/external address. If an existing deployment uses another
reward address and you lack its original complete signing-enabled wallet store,
stop: creating or importing a wallet does not recover that funding authority.

### 3. Wait for this network's rewards, then fund Alice

The scheduled producer creates rewards for `REWARD_ADDRESS`. There is no hosted
faucet or need to obtain real ZEC. With the default 25-second cadence, 100 new
blocks take roughly 42 minutes; this is an estimate, not a readiness guarantee.
Do not lower maturity or start a second miner to skip the wait. Inspect:

```sh
zdn rpc demo getblockcount
zdn wallet sync demo --wallet funding
zdn wallet rewards demo --wallet funding
```

If sync reports `incomplete`, repeat it before classifying rewards. If a read-only
observation reports `chain advanced; retry classified observation`, sync that same
wallet again and retry the observation, not the payment. Another wallet's sync
does not refresh this wallet's store.

Require an owned reward with `mature: true`, `mempool_spent: false`,
`locally_reserved: false`, and enough `value_zat` for amount plus fee. Maturity
is checked at the proposed next block (100-block coinbase rule), not inferred
from elapsed time. Empty rewards can mean the wrong reward address or no owned
blocks; health/RPC readiness is not funding evidence.

For fresh wallets, fund Alice with 1 test ZEC (100,000,000 zat):

```sh
zdn fund demo --funding-wallet funding --wallet alice --amount 1 --fee-zat 15000
```

This shields owned mature transparent rewards into Alice's Ironwood address.
The explicit fee suits a single eligible reward input; fragmented inventory may
require a higher backend fee. Do not blindly change fees after an operation has
started. Save its `operation_id` and `txid`. Require exit success, a confirmed
outcome and at least one confirmation; an acknowledgement alone is not receipt.
Set `FUND_TXID` to the `txid` from that funding result before continuing. Then
independently observe Alice's wallet:

```sh
zdn tx demo "$FUND_TXID"
zdn wallet sync demo --wallet alice
zdn wallet balance demo --wallet alice
```

Fresh Alice should have `balance.confirmed_unspent_zat` and
`balance.spendable_zat` of 100,000,000,
with no pending spends or reservations. If sync reports `incomplete`, repeat sync
before interpreting the balance. A reported as-of balance is not a consensus
light-client guarantee; it trusts the selected validating node.

### 4. Alice sends; Bob verifies and spends

```sh
zdn send demo --from alice --to bob --amount 0.1 --fee-zat 10000
```

Set `ALICE_TXID` to the send result's `txid`, then check both wallets:

```sh
zdn tx demo "$ALICE_TXID"
zdn wallet sync demo --wallet bob
zdn wallet balance demo --wallet bob
zdn wallet sync demo --wallet alice
zdn wallet balance demo --wallet alice
```

Require canonical confirmation from `tx`
and Bob's own scan finding 10,000,000 zat spendable, not just Alice's success
message or `pending_zat`. Alice should retain 89,990,000 zat after that payment
and the 10,000-zat fee. Named recipients are looked up only within this network;
they do not send or share the recipient's private key.

Now demonstrate that Bob actually controls the received note:

```sh
zdn send demo --from bob --to alice --amount 0.04 --fee-zat 10000
```

Set `BOB_TXID` to Bob's send result's `txid`, then verify:

```sh
zdn tx demo "$BOB_TXID"
zdn wallet sync demo --wallet alice
zdn wallet balance demo --wallet alice
zdn wallet sync demo --wallet bob
zdn wallet balance demo --wallet bob
```

With only these three payments, final
confirmed/spendable balances should be Alice **93,990,000 zat** and Bob
**5,990,000 zat** (0.9399 / 0.0599 test ZEC). Check no pending spends or local
reservations reduce these values. These expectations use the explicit fees
above and are not claimed observations from a new live run.

### If interrupted; when finished

Fund/send print and durably save the operation UUID before network effects.
If a command times out, sync is incomplete, or the reply is lost, preserve the
whole store. Inspect `zdn wallet journal demo`, then use `zdn tx demo TXID` when
known. Resume the **same** original command with `--operation-id UUID`, unchanged
sender, recipient, amount and fee. Do not run a fresh payment, delete its journal,
or manually `zdn submit` its bytes to recover. See [durable payments](#durable-funding-payments-and-status).

Stop all writers before a coherent whole-store backup. Copy the entire wallet
root, including network journals/payment-data/scan files and backend settings,
plus controller state/receipts to private local storage; a key-only copy or import
does not restore signing authority. Preserve backend source/notices and the
verified executable pin separately. Follow the README's
[disposable-team cleanup](../README.md#4-tear-down-the-network-and-disposable-team)
once, after stopping connections and writers. Cleanup deletes test-chain data,
not your local keys or backups; a failed cleanup is not success.

## Transparent sending and receiving

**Local implementation; live-node acceptance and updated distribution remain
unqualified.** Ironwood stays the default. Transparent mode uses the same
network-scoped wallets, private connection, input reservations, operation IDs
and original-transaction recovery. It adds no crypto dependency to ZDN itself.
The separately selected backend must advertise `transparent-wallet-payments/v1`
and snapshot-payment/v2; transparent balances also require
`transparent-wallet-state-observation/v1`. Older backends fail closed rather
than silently sending from another pool. The older release/source pins above
do not imply transparent support; use an explicitly reviewed matching backend.

For receiving, verify the local wallet with:

```sh
zdn wallet show demo --wallet alice
```

Its `public.reward_address` is the existing **Testnet P2PKH transparent receiving
address**. Despite the historical field name, it also receives ordinary payments.
Share only that public address, never the key or private wallet store. ZDN can
send to a local recipient name or an explicit Testnet P2PKH/P2SH address;
owned input selection and received-balance scanning support this wallet's P2PKH
key, not imported arbitrary P2SH scripts or Mainnet funds.

```sh
zdn wallet balance demo --wallet alice --pool transparent
zdn send demo --from alice --to bob --pool transparent --amount 0.1
zdn wallet sync demo --wallet bob
zdn wallet balance demo --wallet bob --pool transparent
zdn send demo --from bob --to alice --pool transparent --amount 0.01
```

Require a confirmed outcome, then independently check Bob's balance and fresh
spend of the received output; a transaction acknowledgement alone is not receipt.
Transparent balance excludes **all coinbase rewards**, including mature ones.
It reports normal confirmed UTXOs, pending receipts/spends and existing local
reservations. `--confirmed-only` leaves current classifications unknown rather
than claiming spendability. `wallet rewards` remains the coinbase inventory.

### Funding transparent balances from mined rewards

Zcash requires a transparent coinbase output's first spend to have no transparent
outputs, including change, even after 100-block maturity. This is not a new ZDN
policy. To start with mined rewards, shield them with the existing default
`fund`, then explicitly unshield into a transparent wallet:

```sh
zdn fund demo --funding-wallet funding --wallet funding --amount 1
zdn fund demo --funding-wallet funding --wallet alice --pool transparent --amount 0.5
```

Wait for each payment's confirmation before the next step. The second command
requires sufficient existing Ironwood funds; it never spends coinbase directly
or silently switches input pools. **Its change is transparent to the sender:**
the entire selected Ironwood input value, less the fee, leaves the shielded pool,
not only Alice's requested amount. Transparent sends then spend normal P2PKH
UTXOs with transparent change and need no shielded proof. Funding from Ironwood
still generates a real shielded proof in the trusted local backend.

On interruption, retain the complete wallet store and repeat the **same pool**,
sender, recipient, amount and fee with `--operation-id ORIGINAL_UUID`. Do not
create a fresh operation to work around an unknown outcome, switch pools on
resume or replace original signed bytes. No live-node, proof-generation or AWS
run is authorized by these instructions; follow the repository approval rules.

## Advanced reference: backend, storage and recovery

The sections below define command interfaces, observation limits and recovery
barriers. They are reference material, not extra steps before the walkthrough.

### Backend trust and low-level key/scan commands

No wallet, crypto or node dependency is linked into zdn. Supply a separately
built, trusted local Ironwood backend and its independently verified executable
SHA256 once with `zdn wallet backend set --backend PATH --backend-sha256 HASH`.
Backend-using create/import/show/key/scan/sync/balance/rewards/fund/send/archive-payment
commands use that wallet root's saved pair and verify executable bytes on every
use. A complete explicit pair overrides it for one command; partial pairs refuse.
Local `list`, `journal`, `journal-migrate`, `journal-enable-settlements`,
`cancel-payment`, backend-free read-only-network `journal-reconcile`, and
transport-only `history-export` need neither a key nor a backend. They refuse
backend-selection flags and never read backend settings, even if damaged.
There is no PATH lookup, automatic trust-by-hashing, download, release selection
or wrapper fallback. A hash identifies bytes, not their trustworthiness; obtain
it independently, not by hashing an untrusted download and declaring it verified.

These low-level commands are for explicit key/scan tasks, not named-wallet
creation or payment recovery. A key-only import cannot restore signing authority.

```sh
umask 077
mkdir -m 700 ./private-wallet
IW=/absolute/path/to/ironwood-wallet
IW_SHA256='REPLACE_WITH_64_HEX_EXECUTABLE_SHA256_FROM_YOUR_VERIFIED_BUILD'
zdn wallet backend set --backend "$IW" --backend-sha256 "$IW_SHA256"
zdn wallet key-create ./private-wallet/key.json
zdn wallet key-public ./private-wallet/key.json
zdn wallet key-import ./private-wallet/key.json ./private-wallet/copy.json
zdn wallet scan ./private-wallet/key.json ./trusted-history.json ./private-wallet/scan.json
```

Use normal (default human) mode: key/scan success prints the backend's exact
public JSON contract; history/balance print zdn's observation JSON described below.
`--format json/jsonl` remains unsupported and executes nothing.
The backend must be a regular executable, not a symlink; its bytes are hashed
before execution. Input keys must be regular private files with no group/other
permissions. No path may contain symlinks. Output parents must be private
directories and outputs must not exist. Keep all paths/backend under your control
throughout execution: preflight checks do not eliminate concurrent path replacement
or sandbox a malicious backend.

zdn never loads private key contents. The backend owns key generation, private
schema/import validation, history parsing and exclusive mode-0600 file and parent
fsync writes. Keys are plaintext, not mnemonic/HD/encrypted storage. A backend
failure, crash, process limit, invalid response or post-write permission failure
may leave a partial or complete new output. zdn does **not** roll it back; inspect
locally and use a new destination, never assume a failed operation created nothing.

Key/scan output has a 1 MiB limit per stdout/stderr pipe and a 60-second deadline
with process-group cleanup. Raw backend stderr and parse diagnostics are not
forwarded. Exact JSON shapes reject extra fields, including nested note fields,
before any stdout is emitted. Key responses require schema 1, `network: "test"`,
a checksummed Testnet P2PKH reward address, 33-byte compressed SEC public key and
43-byte raw Ironwood address. Cryptographic validity belongs to the pinned backend,
not zdn's encoding checks.

Scan responses require schema 1, bounded tip/commitment/note indices and counts,
32-byte tip/digest/anchor hex, and public notes with txid, action_index, unique
position, positive value_zat and spent. They have exactly the backend's fields,
without an invented network field. Their scope is **only the supplied trusted
exported history, never a current network balance**. Large summaries can hit
zdn's 1 MiB output cap even inside backend history bounds.

The contract follows the supplied wallet source's `src/{main,keys,history}.rs`
and README. History is a full-block JSON export for `h0-testnet-nu6.3-at-1`,
Testnet genesis `05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38`,
with schema_version, network, genesis_hash, blocks and treestate. Backend limits:
4096 blocks, 64 MiB raw blocks, 16384 commitments, 129 MiB input JSON. Backend
validation does not establish consensus, PoW, canonical selection or tip freshness;
the caller must trust the selected validating node.

### Named wallets

Create/import/list/show select a saved NETWORK or reviewed imported endpoints.
Create also accepts an existing local network binding before deployment; the
other commands require deployed endpoints, as for `rpc`.
They resolve the manifest from the explicitly selected saved deployment, or accept
an explicit `--manifest` override that must match it. Before deployment, creation
can use the reviewed bytes registered by `identity bind --manifest FILE` (below),
or the existing explicit `--manifest` long form. Manifest schedule, endpoint
fingerprint and wallet binding checks remain mandatory. Imported endpoint files
still need an explicit `--manifest`; no manifest is guessed or fetched.
**None of create/import/list/show invokes AWS or opens a tunnel**. Imported endpoint parsing still requires
an explicit `--aws-profile`, but these local operations do not authenticate it.

```sh
zdn wallet create demo --name alice
zdn wallet import demo --name observer --source-keyfile ./private-wallet/key.json
zdn wallet list demo
zdn wallet show demo --wallet alice
zdn wallet balance demo --wallet alice
```

Here `demo` is an unambiguous saved network label; full IDs and unique prefixes
also work. Always select a network explicitly. To override the configured backend,
put both flags before the wallet leaf: `zdn wallet --backend PATH
--backend-sha256 HASH show demo --wallet alice`. Fund/send accept that pair on
their own command. Settings live in private `WALLET_ROOT/backend.json`; configure
each custom `--wallet-dir` separately. No backend settings are loaded by `tx`.

Names start with a lowercase ASCII letter and contain only lowercase letters,
digits or hyphens, at most 64 bytes. Names resolve within the **network UUID**, not
just its consensus fingerprint. Storage is `XDG_DATA_HOME/zdn/wallets/UUID/NAME/`
(otherwise `~/.local/share/zdn/wallets/UUID/NAME/`), or use root-level
`wallet --wallet-dir ROOT ...`. Directories are 0700; backend-owned `key.json`
and public `wallet.json` receipts are 0600. Receipts bind wallet UUID/name,
network UUID, consensus fingerprint, public keys and creation-backend hash.
Each invocation still pins its selected executable; the creation hash is provenance,
not a requirement to use that same build forever. Show/named balance re-derive
public keys and reject a changed identity **before AWS**.

New named-wallet receipts use schema version 2 with a required boolean
`scan_only`: `create` generates a new key with `false`; bare-key `import` records
`true`. Imported wallets can be listed, shown, synced, queried for balances/rewards
and used as named recipients. They cannot act as the sender of `fund` or `send`,
including with `--operation-id`: those commands refuse before opening the payment
journal, invoking the backend or contacting AWS. Completing a scan does not enable
signing. There is no key-only signing override or in-place upgrade command.
On-chain spendability classifications are not signing authorization.

To recover signing/payment authority, restore the **complete coherent store of a
signing-enabled wallet**, not just its key. An imported wallet's own complete
backup remains scan-only. Version-2 receipts missing the policy or carrying a
non-boolean policy refuse; old readers reject the new receipt version. Complete
legacy version-1 stores remain readable and recoverable, but v1 never recorded
whether a key was created or imported. This change cannot retroactively identify
old bare-key imports. Do not edit receipts, remove policy fields or downgrade a
new store to bypass a refusal. Local controller/backup rollback remains outside
the trusted-storage guarantee.

#### Create the reward wallet before deployment

After normal team setup, bind the intended configuration locally and create its
fresh signing-enabled funding wallet **before** choosing the deployment reward
address. For the README's default path, first run its `init --name demo ...
--nodes 1` once; do not repeat init if that configuration already exists.
Use the same default `devnet.yaml`, saved profile and state for later deployment.
Keep local state outside the configuration source directory/Git worktree.

```sh
zdn identity bind --manifest "$CHAIN_MANIFEST"
```

Set `NETWORK` to the exact `network_id` UUID printed by bind, then create the
funding wallet using the trusted program and hash from
[wallet setup](#1-obtain-the-matching-wallet-program):

```sh
zdn wallet backend set --backend "$IW" --backend-sha256 "$IW_SHA256"
zdn wallet create "$NETWORK" --name funding
```

Binding derives team/account/region from `devnet.yaml`'s saved local profile.
For explicit offline use without a saved profile, all three scope flags remain
available; partial scopes or disagreement with a saved profile refuse. Manifest
registration preserves the exact reviewed bytes once, bound to the network UUID.
Repeating it with identical bytes is safe; replacement bytes refuse. Later
creation, deployment and wallet selection must agree with the registered consensus
fingerprint. A damaged registration is not ignored or overwritten. Keep this state
with the network's recovery records.

Pass the creation receipt's `public.reward_address` to the normal deployment's
`--reward-address`, with that same reviewed manifest and network binding. Retain
the complete wallet root's `UUID/funding/` store, not an exported key reimported under a
new name. Once deployed, use this original wallet for reward scanning/funding.
Creation does not reserve cloud resources, establish readiness or check funds.
An existing saved deployment still requires its validated endpoint/manifest
binding; corrupt or incomplete deployment authority does not silently fall back
to the predeployment path. Check actual rewards and confirmed payments after
deployment; local creation alone does not prove the funding path works.

For custom locations, pass the same `--state-dir` and configuration/profile
selection consistently to bind, create and deployment. Set a custom root with
`zdn wallet --wallet-dir ROOT backend set ...`, then use that root on every
wallet/payment/status command; settings in another root do not apply here.
See the [complete first-payment walkthrough](#first-payment-alice-and-bob)
for independent Alice/Bob creation, maturity and receipt checks.

Creation reserves an exclusive name directory before the backend runs and fsyncs
directory entries. Duplicates and concurrent creation never replace keys. Failures
preserve the directory and any key/output; do not delete or retry into it blindly.
`list` sorts local receipts by name and reports missing receipts as `incomplete`.
Its `key_verified:false` is deliberate: list never runs the backend or proves a
receipt still matches its key. Show verifies that identity; it does not check funds.
Receipts are local bindings, not signed attestations against a hostile local user.

### Explicit resumable sync and checkpoint recovery (state/v2)

For an existing named wallet, explicitly run:

```sh
zdn wallet sync demo --wallet alice
# Imported endpoints instead of NETWORK:
zdn wallet sync \
  --wallet alice --manifest ./reviewed-consensus.json \
  --endpoints ./endpoints.json --aws-profile participant
```

Repeat the same command to resume. This is **derived scan progress, not a balance,
reward-maturity, mempool, reservation, payment or spendability result**. Named
balance/rewards consume authenticated state when the pinned backend advertises
`ironwood-wallet-state-observation/v2`. New fund/send operations use
`ironwood-wallet-snapshot-payment/v2` (see below). Sync alone does not authorize
payments, and never silently falls back to a full-history scan.

The pinned executable must advertise schema-1 `capabilities` containing
`ironwood-wallet-state/v2`. Capability, manifest, receipt and rederived key-public
checks happen before AWS/RPC effects. The existing network journal lock is held
before any backend database command and throughout the identity-checked private
read-only session. Backend commands own database locks and private decoding;
ZDN neither links crypto nor parses private keys. Payment evidence/reservations
are not changed. Backend executable pinning retains the local-controller trust
boundary described above.

State lives in the named wallet's private directory as `scan-v2.sqlite`, with a
durable exclusive `scan-v2.initialized` initialization-intent marker. Only a truly
new store is initialized. Corrupt, incompatible (including v1), missing-after-use,
symlinked or interrupted-init stores refuse without deletion, replacement or
automatic migration. Preserve all files and inspect/recover explicitly; do not
delete the marker as a repair procedure. Back up this sensitive derived database
and marker with the existing wallet/journal evidence; it is not a key backup or
a substitute for unresolved payment evidence.

Each invocation pins a target, rechecks the stored tip against the selected
canonical chain and sends consecutive batches of at most **256 blocks / 64 MiB raw
/ 129 MiB JSON**. The existing **8 MiB per-RPC response** bound still applies (so
an individual raw block can hit that stricter transport limit). Genesis raw
length/SHA256, hex encoding, treestate height/hash/root and commit receipt ancestry
are checked. Backend parsing owns connected block identities, roots and state/key
authentication. Batch and pinned target canonicality are checked before and after
commit. An unchanged tip fetches no raw blocks. A byte-limited batch may fetch one
non-fitting next block that must be fetched again on resume.

`--max-batches` defaults to 4 and accepts 1–16: at most 1,024 blocks by default or
4,096 at the maximum per invocation, **not a lifetime cap**. The existing session
cancellation/300-second budget, per-RPC deadlines and 60-second bounded backend
invocations also apply. Successful command execution emits height/count/lag,
public state/generation/tip/anchor bindings and recovery
progress: `current_at_observation` means scanned through a canonically observed
tip, never spendable/current funds; `incomplete` means more invocations are needed
(batch budget exhausted or node advanced). Both carry `payment_enabled:false`
and `spendability_checked:false`. No raw keys, notes, addresses or paths appear
in progress.

Session/deadline/backend/observation/cleanup failure returns nonzero without a
successful JSON result. Committed progress survives; stderr labels the last
acknowledged height/generation as unchecked and warns that a lost backend reply
may have committed newer state. Resume revalidates from backend status. A commit
whose final observation failed is only a candidate, never reported current.
Sync advancement failures include allowlisted `stage`/`class` labels (for example,
`backend-append`/`backend-failure`, `rpc-read`/`rpc-transport`, or
`session-check`/`cancelled`). These classify the observed failure, not its remote
root cause. Arbitrary backend diagnostics, RPC bodies and transport details stay
redacted. If cleanup also fails, stderr retains both the safe sync failure and
the incomplete-cleanup warning; cleanup must not replace the original failure.

Rewind capability alone is not permission to upgrade existing storage. Explicitly
opt in with `wallet sync ... --enable-rewind`; the backend must advertise
`ironwood-wallet-state-rewind/v2`. This adds its authenticated checkpoint table;
old strict backend readers refuse the upgraded store. Enablement must preserve
the complete state summary. Four newest batch boundaries **including current**
are retained, with no minimum block-depth promise. Subsequent sync and capable
payments automatically choose the newest retained boundary whose hash is still
canonical, atomically restore the whole state with generation/parent-hash CAS,
and replay replacement blocks within the normal batch budget. Same-height forks
and node rollback are included. Canonicality is checked around rewind commits;
lost or invalid receipts never authorize further collection or a current result.

If no retained canonical boundary exists, ordinary commands refuse unchanged.
Explicit `wallet sync ... --replay-from-genesis` permits a derived pre-genesis
baseline followed by resumable genesis replay; it is not an automatic repair for
a corrupt/missing database. Rewind must already be enabled (or explicitly enabled
in that invocation). Keys, journal and every original payment artifact remain
untouched. Nodes are not garbage-collected; the backend's 2 GiB store and bounded
owned-state limits still apply. These local fixture-qualified mechanics are not
live AWS/node, genuine-proof, physical power-loss, performance or beta qualification.

#### Incremental named balances and rewards

With `ironwood-wallet-state-observation/v2`, named `balance` and `rewards` resume
up to four batches in one locked, authenticated session. Incomplete sync refuses
classification; explicit `sync` advances larger backlogs. The response binds exact
network/consensus identity, authenticated generation/state, canonical tip/anchor
and the collected mempool. No `history_sha256` is invented. ZDN rechecks mempool
and tip before success and subtracts network-wide input reservations, including
same-key aliases and reorg quarantines. Reward maturity is checked at the exact
100-block boundary; transparent rewards are not Ironwood balance.

Named `--confirmed-only` uses the same incremental state but no live mempool or
reservation classification: spendable/pending/immature/reserved fields remain
null. Direct-key balances, export/scan, and noncapable backends retain their
bounded legacy path. After explicitly enabling settlement storage, classified
named balances/rewards require the v2 observation capability rather than using
legacy classification without archive reconciliation.

### Trusted-node history and balances

These commands manage one verified private connection themselves. No separately
running `connect` or `exec` is needed. Select saved NETWORK/`--profile`/`--state-dir`
as for `rpc`, or import reviewed endpoints and select your own AWS profile:

```sh
zdn wallet history-export --endpoints ./endpoints.json --aws-profile participant \
  --manifest ./reviewed-consensus.json --output ./private-wallet/history.json
zdn wallet --backend "$IW" --backend-sha256 "$IW_SHA256" balance ./private-wallet/key.json \
  --endpoints ./endpoints.json --aws-profile participant --manifest ./reviewed-consensus.json
```

The manifest is mandatory, including for imported endpoints. Its canonical
fingerprint must match the selected endpoint file **before any AWS call**. Only
the backend's exact Testnet genesis and pre-NU7-at-1 schedule, with NU7/SLH absent,
are supported. Normal account, fixed SSM document and service-health identity
checks still apply. This is an authenticated trusted-node observation, not
independent consensus validation or a guarantee that an endpoint declaration is
honest. Obtain the manifest/endpoint files from a trusted operator.

Each operation pins the starting tip, collects raw blocks 0..tip by canonical
height/hash, checks genesis bytes against the manifest, and retains the complete
matching `z_gettreestate` response. Bounds are 4096 blocks, 64 MiB raw blocks,
129 MiB encoded history and the existing 8 MiB/10-second limit per RPC. A
300-second collection/scan/observation budget is checked before and after each
RPC; an in-flight RPC can take up to another ten seconds to return. Startup and
session cleanup have their own existing bounds. There are no retries.

`history-export` publishes an exclusive 0600, file-and-parent-fsynced JSON file
**after successful connection cleanup**, never replacing an existing output.
Its file has exactly the backend history schema. It does not parse or verify
block bodies; run `scan` with the selected backend for canonical block/transaction
encoding, connected history, commitments, root and note validation. A failed
directory fsync or stdout write after publication can leave a complete file;
inspect it and never assume failure means no output exists.

`balance` scans that snapshot using the pinned backend in an ephemeral private
directory and, by default, collects a bounded mempool snapshot using
`getrawmempool(false)` and `getrawtransaction(txid,0)`. It invokes the backend's
`balance KEYFILE HISTORY_JSON MEMPOOL_JSON NEW_BALANCE_JSON` interface and checks
the returned height/hash/history digest/anchor/**mempool digest** against the
collected inputs. It reports **only Ironwood notes**, using checked integer
zatoshis; it does not include transparent rewards. The backend sees the private
key path; zdn never reads key contents. Temporary history/scan files are removed
on normal return; no wallet database or persistent balance cache is created.

Both commands observe the final node tip and recheck the pinned height's canonical
hash and the observed tip's hash, refusing observed rollback/reorg. Success is
printed only after session liveness/cancellation/cleanup checks pass. The JSON
records `as_of` and `observed_tip` height/hash, `scan_lag_blocks`, `network_id`,
`consensus_fingerprint`, `history_sha256` (backend length-prefixed raw-block digest),
`anchor_hex`, `snapshot_tip_canonical_at_observation:true`, and
`consensus_validated_by_zdn:false`. Export also reports the output path and
`history_file_sha256`, which is the SHA256 of the exact encoded file and is
different from the backend digest.

Classified balance additionally requires the chain tip to stay exactly pinned
before mempool collection and through the final observation. The sorted mempool
txid set is rechecked after backend processing; a changed set, tip advance,
rollback or reorg refuses success, with no automatic retry. Mempool limits:
1024 transactions, 64 MiB aggregate raw bytes, 129 MiB encoded JSON and the existing
per-RPC limits. The mempool digest is SHA256 of ASCII
`ironwood-wallet-mempool/v1`, NUL, then each sorted txid's
`u64_le(raw_byte_length) || raw_bytes`. The backend checks canonical v6/NU6.3
transactions, recomputed unique txids and conflicting/chain-used Ironwood nullifiers.
It trusts the validating node; it does not independently validate those proofs.

The `balance` object has `pool:"ironwood"`, `mempool_sha256`, and:

| Field | Meaning |
| --- | --- |
| `confirmed_unspent_zat` | Gross owned chain-unspent notes, including notes consumed by a mempool transaction. |
| `spendable_zat` | Confirmed notes not consumed in that mempool snapshot; named balances also subtract matching local reservations. Direct-key balances do not inspect the journal. |
| `reserved_zat` | Named balances only: owned chain-unspent notes reserved locally but not already counted as mempool-spent. |
| `pending_spent_zat` | Gross confirmed input value consumed in the mempool, not the payment amount or fee. |
| `pending_zat` | Gross incoming mempool notes, including own change, excluding notes spent within the snapshot. Not net incoming/outgoing. |
| `immature_zat` | Zero for this Ironwood-only summary. The transparent coinbase 100-block maturity rule is not imposed on Ironwood anchors. |

The top level records `mempool_snapshot_rechecked:true` and
`local_reservations_checked:true` for named classified balances (false for direct keys
and confirmed-only scans). Named classification uses the backend's `balance-reserved`
interface with the network journal's input exclusions. Even unchanged observations are not an
atomic/current balance guarantee: chain/mempool state can change immediately
after checking. The network lock covers collection, classification and cleanup.

Use `balance ... --confirmed-only` with an older scan-only backend or when an
as-of chain scan is intended. It permits a positive observed scan lag and returns
`unspent_note_count` with `spendable_zat`, `pending_zat`, `immature_zat` explicitly
**null (unknown), not zero**. It does not read the mempool or silently fall back
from failed classification. Normal balance requires a backend implementing the
balance command; a key/scan-only backend is insufficient.

### Durable funding, payments and status

These commands use the same reviewed manifest, saved network or imported endpoints,
AWS profile, fixed SSM documents and private service identity checks as balance.
They acquire their own scoped connection. `fund` defaults to the local named
`funding` wallet, which must already belong to a complete signing-enabled store.
Importing a deployment reward key permits observation only, not funding.
Preserve the complete original funding store for recovery. Newly created wallets
can spend funds received at their own addresses; creating one does not transfer
authority over an external reward key.
Connection permission alone does not supply another person's wallet key.

```sh
zdn wallet rewards demo
zdn fund demo --wallet alice --amount 1
zdn fund demo --address "$RECIPIENT" --amount 0.25
zdn send demo --from alice --to bob --amount 0.37
zdn tx demo TRANSACTION_ID
```

All accept `--wallet-dir ROOT` for the same local store. `rewards` reports owned
unspent P2PKH coinbase outpoints, values, mined heights, target-height maturity,
mempool spends and local reservations; it does not invent available inventory.
With the default `--pool ironwood`, `fund` prefers sufficient eligible Ironwood notes; otherwise it shields only owned
mature P2PKH rewards. It never mixes input pools. `send` uses only the named
sender's Ironwood notes. Both use deterministic largest-first selection bounded to
32 inputs, Ironwood recipient outputs and internal-scope Ironwood change. They
never fall back to another pool, another wallet or transparent change. Explicit
`--pool transparent` has the distinct behavior and capability requirements
described in [transparent sending and receiving](#transparent-sending-and-receiving).

Amounts are decimal ZEC with at most eight fractional places, parsed to integer
zatoshis without floats. `--fee-zat` is an optional explicit integer fee; otherwise
the backend uses its conservative Common ZIP317 rule (5,000 zat marginal fee,
not the selected node's lower 400-zat marginal fee). A typical one-reward shielding
payment costs 15,000 zat and a two-action Ironwood payment 10,000 zat; fragmentation
can increase that fee. Explicit fees below the backend floor refuse before proving.
`--to` accepts a network-local wallet name, raw 43-byte Ironwood receiver hex or a
Testnet Unified Address decoded by the pinned backend. A UA must have an
Orchard-format receiver for this explicitly Ironwood transaction; prefixes alone
do not establish compatibility. Mainnet, receiver-less and invalid addresses refuse.

Before any AWS operation, the CLI saves a new operation UUID and payment intent.
It retains an immutable request, original preparation evidence, a
backend-authenticated plan, exact signed bytes and txid. The backend's opaque
`plan_authorization_hex` binds every typed plan field to the sender key.

#### Snapshot-bound v2 payments

New fund/send operations with capability `ironwood-wallet-snapshot-payment/v2`
also require state/v2 and the reviewed scoped identity. Under the network lock,
one authenticated RPC session resumes the sender's named-wallet scan in at most
four batches (256 blocks/64 MiB raw per batch). Incomplete sync refuses payment
preparation, retaining the operation UUID for an identical retry. Use explicit
`wallet sync --max-batches 1..16` to advance larger backlogs. There is no complete
history JSON or genesis-rescan dependency on warm payment preparation.

`snapshot-create` freezes the exact generation/state, witnesses, request,
exclusions and mempool. `prepare-snapshot-payment` publishes a strict schema-2
plan with scoped identity, snapshot/state digests, generation, tip, anchor,
mempool digest, authenticated economic `allocation` and authorization. No
`history_sha256` is fabricated. `construct-snapshot-payment` runs only after
durable signing intent; strict schema-2 envelopes retain the complete plan,
txid, exact raw bytes and `broadcast:false`. `check-snapshot-transaction` must
authenticate all original bindings and the domain-separated typed plan digest
before journal adoption or dispatch. The shared reservation, cancellation,
dispatch, alias guard and indexed journal semantics apply to both versions.

Original v2 evidence lives in `payment-data/UUID/`: `identity.json`,
`request.json`, `context.json`, `snapshot-started`, `snapshot.json`, `plan.json`
and `transaction.json`. Keep it all. Snapshot publication intent prevents an
absent original from silently being recreated. Lost/corrupt originals block
recovery; restoring them permits rechecking **only the same transaction**.
Recovery needs neither the mutable scan database nor replay of history. It
explicitly verifies `canonicality:original_preparation_only_not_live_checked`:
this is not a current spendability or reorg-safety assertion. Live status still
checks canonical inclusion before any exact-byte redispatch. Enabled retained
checkpoint recovery applies before new preparation; deep replay remains explicit.
Settled-archive reconciliation runs again after sync, before input selection,
so a reorg detected during synchronization cannot bypass an archived guard.

Saved v1 plans always retain the exact original `check-transaction` and
history/mempool recovery path, even with a newer v2-capable executable. They
are never upgraded, reselected or reconstructed. Backends not advertising v2
retain legacy bounded preparation (`prepare-payment`, `construct-payment`,
`check-transaction`); capability discovery does not relax schema-1 responses.

On the legacy path, before preparing a new plan or classifying a balance/reward inventory, history
collection catches up with mining by fetching only blocks added during the
initial full scan. The fetched prefix
must remain canonical, and preparation/reservation still require zero observed
lag and an unchanged mempool. This is in-session catch-up, not persistent
incremental synchronization; the normal history size and session-time limits
still apply. Confirmed-only balances and history exports keep their existing
as-of behavior. A chain or mempool change after the classified snapshot is
frozen still refuses the result rather than publishing stale classifications.

One nonblocking network-wide `payments.lock` serializes conflicting operations
across wallet aliases. Journal records live at `ROOT/NETWORK_UUID/payments/UUID.json`;
snapshots/envelopes live under `payment-data/UUID/`. These directories and names
are reserved, including for wallet creation. Existing colliding wallets fail closed
for explicit migration; their files are never deleted or repurposed. JSON writes
are private and file/parent-fsynced. Legacy record bounds are 4 MiB each, 1,024 operations,
64 MiB aggregate; backend exclusions are bounded to 4,096 inputs. Explicit indexed
migration below retains these bounds for **active** work. Unsupported or
corrupt records, stray journal files and crash-left temporary files refuse rather
than reset the store. Do not remove a lock file or edit a payment to bypass a refusal.

New plan reservations (`outcome.kind: reserved`) durably establish that signing
has not started, so an interrupted pre-sign recheck can resume its original plan
without an envelope. Legacy planned records are not promoted to this state.
Signing intent (`outcome.kind: signing`) is durable **before** constructing or
adopting/revalidating an unjournaled envelope. If signing is interrupted, a missing
envelope does not prove that no signed bytes exist: the operation remains
quarantined, with its reservations and same-key replacement guard retained.
Resume can validate and adopt the original envelope, but never reconstructs a
missing one after signing intent. Legacy planned records are likewise ambiguous:
they block new same-key payments and require the original envelope on resume.
Neither `signed:null` nor zero attempts establishes unsignedness. Existing schema version 1 records
remain readable; older strict readers reject the new `reserved` and `signing`
outcomes and refuse the whole scope while either is present. Do not downgrade or
edit the journal to bypass this barrier.

#### Local unsigned cancellation

```sh
zdn wallet --wallet-dir ./wallets cancel-payment --endpoints ./endpoints.json --aws-profile participant \
  --manifest ./reviewed-consensus.json --operation-id OPERATION_UUID
# Review proposal_sha256, eligibility and reason, then repeat with:
zdn wallet --wallet-dir ./wallets cancel-payment --endpoints ./endpoints.json --aws-profile participant \
  --manifest ./reviewed-consensus.json --operation-id OPERATION_UUID --apply PREVIEW_SHA256
```

This is local-only: omit backend flags. It never opens keys, runs a backend or
connects to RPC/AWS. Network selection uses the same local manifest/endpoints or
saved network selection as other wallet commands. Preview does not modify payment
records (opening the scope may create its lock/directory). Live evidence is explicitly
**unchecked**. Output contains identity/digest/action metadata, not raw requests,
plans, envelopes or paths. The domain-separated proposal hashes the complete
canonical typed record, including network/consensus/wallet/operation scope and the
cancellation action. Apply re-reads and validates the whole scope under the same
network-wide lock; changed records, wrong-scope or tampered tokens refuse.

Only unplanned `prepared`/`not_dispatched` records with no signed envelope or
attempts, and new unsigned `reserved` records, are eligible. Legacy planned
`prepared`/`not_dispatched`, `signing` (even with missing artifacts), signed and
dispatched records refuse. Absence, rejection, expiry and zero attempts do not
authorize signed cancellation. There is no force unlock.

Apply retains the original request, plan and input audit data plus the committed
proposal hash in a strict terminal `cancelled` outcome. Its inputs no longer
reserve funds or conflict with new operations, and it no longer blocks fresh
same-key/alias payments. The original ID cannot be reused or resumed; repeated
apply refuses as stale/terminal rather than claiming a new success. All transition
APIs retain terminality. **Do not downgrade binaries:** older strict readers reject
`cancelled` and fail the entire scope while its tombstone is present. Never delete
or edit tombstones to bypass that barrier. Cancelled records still count against
legacy limits until explicit migration. Indexed tombstones remain queryable by
ID and in inventory but no longer occupy the active-work budget. This is unsigned
cancellation retention, **not signed-settlement archival**: without the separate
explicit settlement upgrade below, every noncancelled record still consumes the
active budget and retains all reservations.

#### Explicit indexed journal migration and local inventory

```sh
zdn wallet --wallet-dir ./wallets journal-migrate --endpoints ./endpoints.json \
  --manifest ./reviewed-consensus.json --aws-profile participant
# Review network/consensus scope, operations and proposal_sha256; then:
zdn wallet --wallet-dir ./wallets journal-migrate --endpoints ./endpoints.json \
  --manifest ./reviewed-consensus.json --aws-profile participant --apply PREVIEW_SHA256
zdn wallet --wallet-dir ./wallets journal --endpoints ./endpoints.json \
  --manifest ./reviewed-consensus.json --aws-profile participant --limit 20
# Next page: add --after NEXT_AFTER. Exact full record: --operation-id UUID.
```

These commands use cancellation's local scope selection and network-wide lock;
omit backend flags. No key, backend, AWS or RPC access occurs. Ordinary payment
commands **never migrate** a legacy scope. Preview binds the complete scope and
records; wrong or stale tokens refuse before staging. Migration preserves every
request, plan, envelope, attempt and outcome, including legacy signing uncertainty.
Once indexed, reapplying a proposal refuses; preview reports already indexed.

The SQLite catalog is separate from the backend's wallet database. Inventory
returns at most 100 summaries (default 20); exact-ID lookup returns one record,
at most 4 MiB. Counts and byte totals are local inventory, not spendability,
disk-space or full-integrity guarantees. `payment-data` snapshots are neither
measured nor garbage-collected here. `next_after` is the last returned ID; an
empty next page ends traversal. Each page is a fresh locked view, not a frozen
multi-command snapshot. Catalog/v1 validates the complete scope on reads;
explicit settlement catalog/v2 uses bounded indexed live work instead.

**Authority/crash boundaries:** under the network lock, apply commits and verifies
the complete import in private `ROOT/NETWORK_UUID/payments.catalog.sqlite` and
fsyncs the database and scope directory before publishing/fsyncing
`payments/.catalog-v1`. This compatibility barrier makes the catalog authoritative
and causes old readers to refuse the scope. All 1,024 allowed legacy records can
migrate without deletion or cancellation. Original UUID JSON files stay
byte-for-byte intact, but are **never fallback authority**. Subsequent record and
cancellation changes are transactional and synchronized before returning.

After interruption before the barrier, normal commands refuse while a staged
catalog exists. Run migration preview/apply again: a complete matching staged
transaction resumes publication. An empty/incomplete/corrupt/mismatching staged DB
fails closed with inspection guidance; retain a backup of **all** files and move
only the reported staged DB and its SQLite recovery files aside for offline
inspection before explicitly retrying. Do this only with no writer running and
**no authority barrier**. A crash-left temporary file or unknown legacy file is
also a manual inspection blocker, never automatically deleted. An old binary may
still edit legacy records before the barrier exists; resume checks the complete
typed import and refuses any resulting mismatch rather than selecting one copy.

After the barrier, missing/corrupt/unsupported catalog storage always refuses,
including maintenance; restore a coherent compatible backup. **Never remove the
barrier, downgrade, or copy old UUID JSON over the catalog to bypass a refusal.**
Retain keys, wallet bindings, catalog, barrier, legacy originals and payment-data
snapshots/envelopes as one backup set. Stop all writers (or hold the network lock)
before copying it, including any SQLite recovery journal. A disk-full/fsync error
is not proof that a commit failed: keep everything, recover space outside payment
storage, and inspect/reopen before retrying. No automated repair, deletion or
backup/export is provided. Catalog/v1 still costs lifetime validation I/O;
explicit settlement/v2 below selects the indexed trusted-local-storage boundary.

Contributor coverage and the older-reader compatibility check are described in
the [test coverage notes](testing.md#subsystem-coverage-notes).

#### Explicit settled archival and reorg quarantine

```sh
# After journal-migrate, preview the separate local format upgrade:
zdn wallet --wallet-dir ./wallets journal-enable-settlements --endpoints ./endpoints.json \
  --manifest ./reviewed-consensus.json --aws-profile participant
# Review proposal_sha256, then repeat with --apply PREVIEW_SHA256.
zdn wallet --wallet-dir ./wallets journal-reconcile --endpoints ./endpoints.json \
  --manifest ./reviewed-consensus.json --aws-profile participant
zdn wallet --wallet-dir ./wallets --backend "$IW" --backend-sha256 "$IW_SHA256" \
  archive-payment --wallet alice --operation-id ORIGINAL_OPERATION_UUID \
  --settlement-depth 10 --endpoints ./endpoints.json \
  --manifest ./reviewed-consensus.json --aws-profile participant
# Review proposal_sha256; repeat the exact command with --apply PREVIEW_SHA256.
```

Depth is a required explicit policy (inclusion counts as block one), **not
finality**; the example's 10 is not a safety recommendation. Preview/apply bind
the complete original record, scope, chosen canonical tip, exact inclusion and
depth. Advancing/changing the tip or any bound input invalidates the proposal.
The pinned backend first verifies the complete original transaction against its
immutable evidence and original wallet binding. Fresh read-only RPC must then
confirm that exact txid occurs once in its recorded canonical block at sufficient
depth. Missing/orphaned/wrong inclusion, missing evidence, stale proposals and
transport failures never release an uncertain signed payment. Maintenance never
submits transactions or changes cloud resources; session cleanup failure reports
failure even if the preceding durable local archive commit succeeded. Inspect
the original ID rather than infer that failure means no commit.

Upgrade is an atomic SQLite `user_version=2` transition. Prior catalog/v1 readers
reject the version; older pre-catalog readers still reject the existing barrier.
Do not downgrade or remove either gate. Complete original records and independent
`payment-data` evidence remain intact; only separate storage placement and a
scope/record-bound settlement receipt change. Archives leave the active
1,024-operation/64 MiB budget but remain queryable by ID and keyset pages. No
signed evidence is deleted, no operation ID is reusable, and no expiry/absence/
node-rejection force unlock exists. Inventory distinguishes archived settlements,
reorg quarantines and pending reconciliation. Backup copies must include every
key/binding, catalog/barrier/recovery file, legacy original, immutable payment
artifact, and derived scan database/marker/checkpoints, under the network lock or
with all writers stopped. Keys alone are not a recoverable payment backup.

Before new input selection or classified spendability, fresh canonical observations
reconcile the settlement cursor. An unchanged/extended canonical cursor avoids
lifetime archive payload reads. After a fork/rollback, indexed inclusion checks
atomically restore orphaned signed payments' input and same-key/alias guards as
`reorg_quarantine`, without rewriting their historical economic record or
rebroadcasting. A durable pending marker blocks selection across interruptions;
`journal-reconcile` explicitly resumes it without a backend. `journal` inspection
and exact-ID lookup remain available while pending. A blocked fresh attempt can
leave an unsigned prepared intent; cancel that intent explicitly if unwanted.

Reorg quarantine cannot silently disappear to satisfy active quotas. Classification
materializes at most 1,024 ordinary records/64 MiB plus a separate 1,024-record/
64 MiB quarantine read budget; a larger quarantine refuses classification while
all SQL guards and paginated inspection remain intact. Archived/quarantined IDs
refuse ordinary fund/send resume. There is no archived
redispatch, quarantine force release or signed-expiry cancellation. Preserve and
inspect the exact original evidence; those transitions need a separate explicit
policy, not hand editing. Active signing/broadcast-uncertainty recovery retains
the existing same-operation flow.

Catalog/v2 trusts transactional SQLite indexes as local controller authority;
it is not a hostile-storage authenticated tree. Consulted payloads/receipts and
index correspondence are checked, but unconsulted corruption may remain latent.
No lifetime `quick_check` or payload validation runs on ordinary v2 active reads;
backup rollback, malicious local modification and concurrent controllers remain
outside this trust boundary. Do not mistake inventory for a full integrity audit.
Disk usage still grows with retained audit data and immutable backend nodes.

Dispatch uncertainty and the incremented attempt count are durable **before** any
possible network write. Acknowledgement is not confirmation. `fund`/`send` wait for
one confirmation by default (`--confirmations 1..100`, `--wait-secs 1..240`, default
120). Timeout exits unsuccessfully with operation ID, txid, known outcome and
observed depth. Session cleanup failure also refuses command success without
undoing any known payment outcome. The verified-session RPC budget is 300 seconds;
backend proof/recovery calls are individually bounded to 240 seconds, with the
existing 1 MiB per-pipe output bound. A running proof may consume most of the
session budget; resume the saved operation instead of starting a new payment.

After interruption, repeat the **identical** fund/send intent with
`--operation-id ORIGINAL_OPERATION_UUID`. Sender, destination, amount and explicit
fee must match. A fresh payment refuses while the same public key identity has a
planned-without-envelope, signing, signed, uncertain, acknowledged or reorged
payment, including through a wallet alias; using different inputs must not turn
a lost reply into a second payment.
The CLI first observes that txid; only explicit node not-found
permits rebroadcasting the same bytes. Network/lookup failures never mean absence.
Node rejection retains its code and reservations; no replacement is created.
A rejection after a redispatch also blocks new payments from that sender: it
cannot rule out an earlier dispatch whose reply was lost. Resume and reconcile
the original operation instead of paying again with different inputs.
`tx` is read-only on the network, updates local observations, checks canonical
inclusion and reports current confirmations or reorg. It never rebroadcasts.
Do not submit this journal's signed bytes through the separate `zdn submit`
command. That command does not record a wallet dispatch attempt; a Signed
operation with no recorded attempt cannot advance to confirmed settlement or
archival and continues blocking the sender. Resume fund/send with its original
operation ID instead.

Without explicit eligible archival, all reservations remain, including after
rejection, confirmation and reorg; no automatic abandon/release/expiry mechanism
is provided. Preserve the complete store and its
original snapshots, not just key backups, for payment recovery. Legacy full rescans
are bounded to 4,096 blocks; named sync and capable new payments use bounded
resumable state/v2 with explicitly enabled checkpoint recovery. There is no
independent consensus verification or automatic deep reset. These are deliberate bounded prototype limits,
not a production wallet or atomic/current availability guarantee.

The selected release's [bounded Linux payment results](preview-start.md#4-launch-wait-fund-and-send)
do not qualify other component bytes, Mac live use or general recovery behavior.
Those cases still require separate integrated AWS/live qualification.
Offline CLI tests use local fake AWS/RPC/backend processes and
require neither credentials nor proofs; genuine-proof backend controls are separate.
