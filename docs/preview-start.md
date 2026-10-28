# Install ZDN and start your first network

This walkthrough installs Preview 3 (experimental alpha), creates a disposable one-node network,
optionally sends test coins, and removes the network and team resources.
Use a new private work directory and keep the same shell and saved receipts
through cleanup. Commands that create or delete AWS resources are identified
below; verification commands do not grant permission to run those operations.

For a free local build, first [install the controller and optional wallet from
source](install-source.md), then use [source-installed setup](#source-installed-controller)
below instead of the executable-download profile. The remaining network setup
is shared; local installation does not authorize AWS operations.

**Platform status:** Linux x86-64 has executable downloads; macOS uses the
[source installation](install-source.md) only. Preview 3 contains no Mac
executables or Mac executable-download profiles. Earlier Preview 2 downloads
were blocked by Gatekeeper and have been withdrawn. Source builds do not require
Developer ID signing or notarization. Never remove quarantine, re-sign downloaded
files or bypass Gatekeeper to proceed. Candidate-specific live results are
reported in the release notes, not inferred from a successful local installation.
See [preview limits](preview.md#platform-and-trust-limits).

Experimental custom Testnet for trusted developers in a dedicated development
AWS account. No real funds, Mainnet, production wallet or shared-account tenant
isolation. AWS builds, NAT, hosts, disks and storage cost money. A timeout is not
a spending cap. ZDN trusts the selected validating node and the separately pinned,
unsandboxed local wallet backend; it is not a consensus-verifying light client.
Wallet stores/backups contain plaintext secrets. Deployment credentials can read
and cancel other SSM commands in the configured region absent external denies.

## Source-installed controller

Keep the source guide's absolute `ZDN` and optional physical `IW`/`IW_SHA256`
variables. Do not replace them with the published executable paths/hashes below.
Install Git, AWS CLI v2 >=2.37.4 and the native Session Manager plugin from their
official channels. Source installation does not supply node/chain inputs or a
remote helper. In a new private downloads directory, obtain these exact Preview 3
inputs; verify the pins through your trusted release channel first:

```sh
set -eu
umask 077
SOURCE_INSTALLED=1
mkdir zdn-network-inputs
cd zdn-network-inputs
DOWNLOADS="$PWD"
BASE=https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.3
for asset in zdn-node-source-f39268e2-public.tar.gz zdn-node-source-map.json \
  zdn-chain-manifest.json zdn-chain.tar zdn-0.1.0-preview.3-linux-x86_64; do
  curl --fail --location --output "$asset" "$BASE/$asset"
done
printf '%s\n' \
  'c469315debf3c25385764135a6b34dd9764a47e77a406affac6923fbddcf4cd1  zdn-node-source-f39268e2-public.tar.gz' \
  '8446fd55b31df1dca7158e7abec3918249d2f83339b9b0d6d62c304938afec9b  zdn-node-source-map.json' \
  '7c8b86d229ce3d148ab11cb70582fae51a49ce1c18a4a550aa2b55aedc0d55d3  zdn-chain-manifest.json' \
  'd7a004dd471aff559631201f75001042cf4c1796cc9271cf82b109e1faaa9613  zdn-chain.tar' \
  '335ce83c461a087bb359b2d98f509815061595e9dfdfe57ef2325ff014d0085a  zdn-0.1.0-preview.3-linux-x86_64' > source-inputs.SHA256SUMS
case "$(uname -s)" in
  Darwin) shasum -a 256 -c source-inputs.SHA256SUMS ;;
  Linux) sha256sum -c source-inputs.SHA256SUMS ;;
  *) echo 'Select a qualified native platform' >&2; exit 1 ;;
esac
HOST_HELPER="$DOWNLOADS/zdn-0.1.0-preview.3-linux-x86_64"
chmod 700 "$HOST_HELPER"
```

The Linux controller download is also the Linux x86-64 host/build helper,
including when managing from a Mac. It is not executed locally on the Mac.
Keep corresponding controller source/notices from installation with
these inputs. Skip the executable-download profile below and continue at
[shared local preflight](#shared-local-preflight), then section 2. For payments
retain your source-built wallet path/hash in section 3. Do not use the downloaded
wallet's hash for a local build. This setup does not claim new live qualification.

## 1. Select and verify a profile

Obtain assets from <https://github.com/jonwalch/zdn/releases/tag/v0.1.0-preview.3>.
The release body pins each `SHA256SUMS.PROFILE` list. Compare that list's digest
through a trusted release channel before using it; co-downloaded checksums alone
do not authenticate the publisher. Releases are unsigned. Do not bypass OS trust.

- `manage-linux-x86_64`: Linux controller, node source/map, chain manifest/bundle,
  product source, required notices and this guide. The controller is also the
  Linux host/build helper.
- `pay-linux-x86_64`: the above plus the Linux wallet, wallet source and notices.
- macOS: use the source-installed path above, not an executable-download profile.
  Its remote helper is the same Linux controller asset, not the locally built
  Mac executable. No Mac executable is listed in this release's index.

Download every file named by your profile into a fresh directory. Wallet files
are required for the payment profile, not the management-only profile. Verify:

```sh
# Linux payment profile; use manage-linux-x86_64 if not making payments.
sha256sum SHA256SUMS.pay-linux-x86_64
sha256sum -c SHA256SUMS.pay-linux-x86_64
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
    ZDN="$DOWNLOADS/zdn-0.1.0-preview.3-linux-x86_64"
    HOST_HELPER="$ZDN" ;;
  *) echo 'Use the source-installed path on macOS; do not substitute architectures' >&2; exit 1 ;;
esac
chmod 700 "$ZDN" "$HOST_HELPER"
```

### Shared local preflight

On Apple Silicon only, before the following shared commands, establish a short,
private physical temporary directory and probe a real UNIX socket. This uses the
native `/usr/bin/perl` (5.34.1 on the checked Mac), not Python. Keep `TMPDIR` until
all commands and cleanup have finished:

```sh
test -x /usr/bin/perl
TMPDIR=$(mktemp -d /private/tmp/zdn-p3-XXXXXXXX)
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
TEAM=YOUR_NEW_DISPOSABLE_TEAM
BUCKET=YOUR_NEW_GLOBALLY_UNIQUE_BUCKET
```

Before bootstrap, select a host image and zone in that same region. These AWS
commands are **read-only**; they do not create an instance. Resolve AWS's
[public AL2023 x86-64 parameter](https://docs.aws.amazon.com/linux/al2023/ug/ec2.html#launching-al2023-using-ssm)
to a concrete AMI ID, then inspect it:

```sh
AMI_ID=$(aws ssm get-parameter --profile "$AWS_PROFILE" --region "$REGION" \
  --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query Parameter.Value --output text)
aws ec2 describe-images --profile "$AWS_PROFILE" --region "$REGION" \
  --owners amazon --image-ids "$AMI_ID" \
  --query 'Images[].{Id:ImageId,Name:Name,Architecture:Architecture,State:State}'
aws ec2 describe-availability-zones --profile "$AWS_PROFILE" --region "$REGION" \
  --query 'AvailabilityZones[?State==`available`].ZoneName' --output text
```

Require exactly one Amazon Linux 2023 image with `Architecture: x86_64` and
`State: available`. Stop if lookup fails or the image does not match. Set `ZONE`
to one returned zone; availability alone does not guarantee host capacity or
account quota. Keep this concrete `AMI_ID` for launch and recovery rather than
resolving the moving parameter again during an interrupted operation.

```sh
ZONE=YOUR_SELECTED_ZONE_FROM_THE_OUTPUT
```

After reviewing the values, bootstrap the disposable team. **This command
creates real IAM/backend resources:**

```sh
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
if [ "${SOURCE_INSTALLED:-0}" != 1 ]; then
case "$(uname -s)" in
  Linux)
    IW="$DOWNLOADS/ironwood-wallet-0.1.0-preview.3-linux-x86_64"
    IW_SHA256=308ff96fecbc31f17b714dc37408af5dc407902c412d3e810be66bc3fa9a6bf6 ;;
  *) echo 'Install the wallet from source on macOS first' >&2; exit 1 ;;
esac
chmod 700 "$IW"
fi
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
stores. For the separate wallet archive's extraction layout, source-build
commands, installation and attribution, use [source installation](install-source.md).

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
