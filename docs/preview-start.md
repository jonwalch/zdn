# Install ZDN and start your first network

This walkthrough installs Preview 2, creates a disposable one-node network,
optionally sends test coins, and removes the network and team resources.
Use a new private work directory and keep the same shell and saved receipts
through cleanup. Commands that create or delete AWS resources are identified
below; verification commands do not grant permission to run those operations.

**Platform status:** use the checked Linux x86-64 path for a first installation.
Mac browser-download onboarding is **blocked**: Gatekeeper rejected the published
quarantined controller and wallet downloaded through Chrome. They are not
Developer ID signed or notarized. The Mac commands below document native
developer setup, not a working browser-install path or a current Mac live pass.
Do not remove quarantine, re-sign files or bypass Gatekeeper to proceed.
See [preview limits](preview.md#platform-and-trust-limits).

Experimental custom Testnet for trusted developers in a dedicated development
AWS account. No real funds, Mainnet, production wallet or shared-account tenant
isolation. AWS builds, NAT, hosts, disks and storage cost money. A timeout is not
a spending cap. ZDN trusts the selected validating node and the separately pinned,
unsandboxed local wallet backend; it is not a consensus-verifying light client.
Wallet stores/backups contain plaintext secrets. Deployment credentials can read
and cancel other SSM commands in the configured region absent external denies.

## 1. Select and verify a profile

Obtain assets from <https://github.com/jonwalch/zdn/releases/tag/v0.1.0-preview.2>.
The release body pins each `SHA256SUMS.PROFILE` list. Compare that list's digest
through a trusted release channel before using it; co-downloaded checksums alone
do not authenticate the publisher. Releases are unsigned. Do not bypass OS trust.

- `manage-linux-x86_64`: Linux controller, node source/map, chain manifest/bundle,
  product source, required notices and this guide. The controller is also the
  Linux host/build helper.
- `pay-linux-x86_64`: the above plus the Linux wallet, wallet source and notices.
- Mac profiles, when listed in this release's `distribution.json`, additionally
  require the native controller and the separate Linux helper. Do not substitute
  the Mac executable for the remote Linux helper. Their presence in the release
  does not mean browser installation works; see the platform warning above.

Download every file named by your profile into a fresh directory. Wallet files
are required for the payment profile, not the management-only profile. Verify:

```sh
# Linux payment profile; use manage-linux-x86_64 if not making payments.
sha256sum SHA256SUMS.pay-linux-x86_64
sha256sum -c SHA256SUMS.pay-linux-x86_64
```

For the Mac payment profile, instead use (or select `manage-macos-arm64` for
management without CLI payments):

```sh
shasum -a 256 SHA256SUMS.pay-macos-arm64
shasum -a 256 -c SHA256SUMS.pay-macos-arm64
```

Do not use `--ignore-missing`. Keep sources/licenses/notices with the binaries.
Linux requires x86-64 and GLIBC through 2.34; this is not all-distribution support.
Install Git, AWS CLI v2 2.37.4 or newer and the native AWS Session Manager plugin
from their official channels. Python and local Docker are not required by ZDN.

```sh
umask 077
DOWNLOADS="$PWD"
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    ZDN="$DOWNLOADS/zdn-0.1.0-preview.2-linux-x86_64"
    HOST_HELPER="$ZDN" ;;
  Darwin/arm64)
    ZDN="$DOWNLOADS/zdn-0.1.0-preview.2-macos-arm64"
    HOST_HELPER="$DOWNLOADS/zdn-0.1.0-preview.2-helper-linux-x86_64" ;;
  *) echo 'Select a supported native profile; do not substitute architectures' >&2; exit 1 ;;
esac
chmod 700 "$ZDN" "$HOST_HELPER"
```

On Apple Silicon only, before the following shared commands, establish a short,
private physical temporary directory and probe a real UNIX socket. This uses the
native `/usr/bin/perl` (5.34.1 on the checked Mac), not Python. Keep `TMPDIR` until
all commands and cleanup have finished:

```sh
test -x /usr/bin/perl
TMPDIR=$(mktemp -d /private/tmp/zdn-p2-XXXXXXXX)
test "$(cd "$TMPDIR" && pwd -P)" = "$TMPDIR"
test "$(stat -f %Lp "$TMPDIR")" = 700
export TMPDIR
env -i PATH=/usr/bin:/bin /usr/bin/perl -MIO::Socket::UNIX -MSocket=SOCK_STREAM -e '
    my $path = shift @ARGV;
    my $socket = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $path, Listen => 1)
        or die "UNIX socket listen failed: $!\n";
    -S $path or die "UNIX socket path is missing\n";
    $socket->close or die "UNIX socket close failed: $!\n";
    unlink($path) or die "UNIX socket unlink failed: $!\n";
    print "Native Perl UNIX socket preflight passed ($^V)\n";
' "$TMPDIR/probe.sock"
```

For either selected platform, continue in the same shell:

```sh
"$ZDN" --version
"$ZDN" reference > command-reference.txt
"$ZDN" reference --schema > command-schema.json
mkdir -m 700 source-input work
tar -xzf zdn-node-source-f39268e2-public.tar.gz -C source-input
NODE_SOURCE="$PWD/source-input/node-source"
NODE_REV=8ca2da93655148d39fbb88267f9902743eba6f62
git -C "$NODE_SOURCE" fsck --full --no-reflogs
test "$(git -C "$NODE_SOURCE" rev-parse HEAD)" = "$NODE_REV"
test -z "$(git -C "$NODE_SOURCE" status --porcelain)"
test -z "$(git -C "$NODE_SOURCE" remote)"
CHAIN_MANIFEST="$PWD/zdn-chain-manifest.json"
CHAIN_BUNDLE="$PWD/zdn-chain.tar"
WORK="$PWD/work"
"$ZDN" chain verify --manifest "$CHAIN_MANIFEST" --bundle "$CHAIN_BUNDLE"
"$ZDN" deps install --noninteractive
"$ZDN" doctor
```

Use the extracted node source's own Git identity, as checked above; its source
map records the included files and hashes. No private repository is required.
Byte verification and doctor do not validate AWS credentials or prove readiness.
The product-source archive is the exact binary build revision; the public
repository has maintained documentation. Rust code, manifests and
locks correspond to the build revision recorded in `distribution.json`.

Mac users must never substitute their native executable for the Linux helper.
Never remove quarantine, re-sign files or disable Gatekeeper. Signing/notarization
and OS trust approval are not supplied. After every process and cleanup is
finished, remove the scratch directory with `rmdir "$TMPDIR"` only if empty;
do not force-delete it.

## 2. Configure one AWS login and local defaults

Keep this shell's variables and private files through cleanup. Use an existing
authenticated, administrator-capable, non-root AWS profile for your dedicated
development account. Fill in your own values; these are not working defaults:

```sh
AWS_PROFILE=YOUR_AUTHENTICATED_PROFILE
ACCOUNT_ID=YOUR_TWELVE_DIGIT_ACCOUNT_ID
TRUST_PRINCIPAL=YOUR_EXACT_IAM_USER_OR_ROLE_ARN
REGION=YOUR_AWS_REGION
ZONE=YOUR_AVAILABLE_ZONE
AMI_ID=YOUR_AVAILABLE_AMAZON_LINUX_2023_X86_64_AMI
TEAM=YOUR_NEW_DISPOSABLE_TEAM
BUCKET=YOUR_NEW_GLOBALLY_UNIQUE_BUCKET
"$ZDN" setup bootstrap --aws-profile "$AWS_PROFILE" \
  --trust-principal "$TRUST_PRINCIPAL" --team-id "$TEAM" \
  --account-id "$ACCOUNT_ID" --region "$REGION" --bucket "$BUCKET" \
  --export "$WORK/team.yaml" --yes
```

Replace every placeholder. Setup creates real IAM/backend resources; do not
reuse a shared team's deletion scope. Normal operations use the recorded scoped
deployment role through this same source login. Keep temporary credentials
valid; preserve receipts on expiry and follow the original operation's recovery,
not a replacement build. Never put credentials, wallets or state inside source.

From `WORK`, initialize once and inspect the recipe **before** binding/launch:

```sh
cd "$WORK"
"$ZDN" init --name demo --source "$NODE_SOURCE" --revision "$NODE_REV" \
  --nodes 1 --dockerfile node/zakura/docker/Dockerfile --build-context .
"$ZDN" devnet render
"$ZDN" check
"$ZDN" plan
"$ZDN" identity bind --manifest "$CHAIN_MANIFEST"
```

Require render/check/plan success. They do not create a node or establish payment
qualification. Set `NETWORK` to bind's exact returned `network_id` UUID.
Config/default local profile/state are saved; don't fabricate profile files.

## 3. Optional payments: create signing wallets before launch

For network management without CLI payments, skip wallet setup and set
`REWARD_ADDRESS` to a supported Testnet address whose key you control. A newly
created wallet cannot recover someone else's rewards. For payments, the supplied
backend/source target Common 3.0.0, custom Testnet with NU6.3 at height 1 and no
NU7. They are not general Mainnet/Testnet wallet support. Vizor/Zodl are untested.

```sh
case "$(uname -s)" in
  Linux)
    IW="$DOWNLOADS/ironwood-wallet-0.1.0-preview.2-linux-x86_64"
    IW_SHA256=308ff96fecbc31f17b714dc37408af5dc407902c412d3e810be66bc3fa9a6bf6 ;;
  Darwin)
    IW="$DOWNLOADS/ironwood-wallet-0.1.0-preview.2-macos-arm64"
    IW_SHA256=32586aeb68351864584c36dfae7ac2e43c06965bb1037999a9fdf6829f775ad2 ;;
esac
chmod 700 "$IW"
NETWORK=EXACT_UUID_FROM_BIND
"$IW" capabilities
"$ZDN" wallet backend set --backend "$IW" --backend-sha256 "$IW_SHA256"
"$ZDN" wallet create "$NETWORK" --name funding
"$ZDN" wallet create "$NETWORK" --name alice
"$ZDN" wallet create "$NETWORK" --name bob
```

Require `scan_only:false`, independent public identities and capabilities
`ironwood-wallet-state/v2`, `ironwood-wallet-state-observation/v2` and
`ironwood-wallet-snapshot-payment/v2`. Set `REWARD_ADDRESS` to funding's
`public.reward_address`. Key-only imports are scan-only, not restored signing
stores. The wallet-source archive preserves `experiments/ironwood-wallet/` and
its lockfile, licenses and attribution. To build it instead, use Rust/Cargo
1.97.1 and native C/linker tools, then from that archive's extracted root run:

```sh
cargo build --release --locked --manifest-path experiments/ironwood-wallet/Cargo.toml --bin ironwood-wallet
```

Hash and record your newly built binary separately; do not attribute the
downloaded executable's hash or live results to different bytes.

## 4. Launch, wait, fund and send

The following launch creates billed resources and one source build/host:

```sh
"$ZDN" up --manifest "$CHAIN_MANIFEST" --bundle "$CHAIN_BUNDLE" \
  --host-helper "$HOST_HELPER" --ami-id "$AMI_ID" --availability-zone "$ZONE" \
  --reward-address "$REWARD_ADDRESS" --yes
"$ZDN" devnet health demo
"$ZDN" rpc demo getblockcount
```

For payment users, wait for an actual owned, mature, unspent, unreserved reward
with enough value for amount plus fee. At the normal 25-second cadence the
100-block rule takes roughly 42 minutes, not a guaranteed readiness deadline.
No second miner or maturity override. Poll no faster than once per minute:

```sh
"$ZDN" wallet sync demo --wallet funding
"$ZDN" wallet rewards demo --wallet funding
```

If a bounded scan is incomplete, repeat `wallet sync` until it reaches the
observed tip before asking for classified rewards/balances. Preserve its store;
do not mistake a scan refusal for zero funds or start a replacement wallet.
If a read-only observation refuses with `chain advanced; retry classified
observation`, sync again and retry that observation. A moving tip can invalidate
an otherwise complete observation. This is not permission to repeat a payment:
fund/send recovery must use the original operation UUID as described below.

Only after a sufficient reward reports `mature:true`, `mempool_spent:false` and
`locally_reserved:false`, make the three payments below in order. After each
payment, require confirmation, save its original operation UUID and txid, set
the corresponding TXID variable, and run the following observations before the
next payment. These commands send test coins; they are not dry runs:

```sh
"$ZDN" fund demo --funding-wallet funding --wallet alice --amount 1 --fee-zat 15000 --wait-secs 240
# Set FUND_TXID from the successful result before continuing.
"$ZDN" tx demo "$FUND_TXID"
"$ZDN" wallet sync demo --wallet alice
"$ZDN" wallet balance demo --wallet alice
```

Fresh Alice must have 100,000,000 zat confirmed and spendable. If sync is
incomplete, repeat sync before interpreting a balance, never reset the store.

```sh
"$ZDN" send demo --from alice --to bob --amount 0.1 --fee-zat 10000 --wait-secs 240
# Set ALICE_TXID from the successful result before continuing.
"$ZDN" tx demo "$ALICE_TXID"
"$ZDN" wallet sync demo --wallet bob
"$ZDN" wallet balance demo --wallet bob
"$ZDN" wallet sync demo --wallet alice
"$ZDN" wallet balance demo --wallet alice
```

Bob must independently observe 10,000,000 zat spendable; Alice 89,990,000 zat.
Only then demonstrate Bob's control of the received note:

```sh
"$ZDN" send demo --from bob --to alice --amount 0.04 --fee-zat 10000 --wait-secs 240
# Set BOB_TXID from the successful result before continuing.
"$ZDN" tx demo "$BOB_TXID"
"$ZDN" wallet sync demo --wallet alice
"$ZDN" wallet balance demo --wallet alice
"$ZDN" wallet sync demo --wallet bob
"$ZDN" wallet balance demo --wallet bob
```

Sync and classify each wallet together. If either read-only observation reports
an incomplete scan or a moving tip, resync that same wallet and retry its balance
before continuing; another wallet's sync does not refresh this one's store.

Final expected confirmed/spendable balances: Alice **93,990,000 zat**, Bob
**5,990,000 zat**, no pending/reserved deductions. This asymmetric three-payment
path passed on the exact supplied Linux controller/helper/backend/node capture.
It does not qualify separate people/machines, lightwalletd, GUI wallets, hostile
rollback, multi-node behavior, arbitrary reorgs or full beta/platform support.

## 5. Recovery, backup and removal

A lost reply or timeout is not permission to create a replacement payment.
Inspect `wallet journal demo` and `tx demo TXID`; resume the same original
fund/send arguments with `--operation-id ORIGINAL_UUID`. Preserve signed bytes
and every journal/recovery receipt. If an incomplete scan reports `payment not
prepared`, save its returned operation UUID, sync the sender, then resume those
same arguments with that UUID; do not start a new operation.
Never manually `submit` journaled bytes or
force-unlock/delete uncertain state. Unknown build dispatch likewise must be
inspected/reconciled, not blindly repeated. See [wallet recovery](wallet.md),
[deployment recovery](private-devnet.md#resume), [removal](removal.md) and
[AWS state recovery](aws-state.md).

Stop all local controllers, connections and writers before copying the entire
wallet root (settings, keys, receipts, scan databases/markers, journals, original
payment artifacts), plus configuration and controller receipts, into private
storage. A key-only backup cannot restore payment authority. Keep original files
on any uncertainty. No automatic backup/restore or hostile-rollback guarantee.

Remove only the exact disposable team you created. A failed cleanup is not a
successful cleanup. Run the second command only if the first succeeds:

```sh
"$ZDN" devnet destroy demo --yes --delete-data &&
"$ZDN" setup remove-team --aws-profile "$AWS_PROFILE" --yes --delete-data --writers-stopped
```

Network removal alone retains shared team resources; omitting `--delete-data`
retains data and costs. Final team removal schedules owned KMS deletion after
30 days; PendingDeletion is not physical deletion, STS invalidation or billing
closure. Investigate refusal using original receipts, not wildcard AWS deletion.
The demonstrated Linux run's ZDN teardown and independent scoped resource audit
passed. Public metadata includes only bounded evidence summaries, not wallets,
credentials, account-specific receipts or private qualification bundles.
