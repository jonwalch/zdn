# Install from source: controller and optional wallet

Build ZDN locally on macOS or Linux without an Apple Developer account, signing
certificate, notarization credentials or paid installer. Homebrew is an optional
build/install manager, not a requirement. Compilation needs Internet access for
Rust registry dependencies unless you already have a complete Cargo cache.
Linux x86-64 users can alternatively use the verified `manage-linux-x86_64` or
`pay-linux-x86_64` [release profile](preview-start.md#1-select-and-verify-a-profile).

This installs **two separate programs**:

| Program | Purpose | Needed for |
| --- | --- | --- |
| `zdn` | Local controller; manages remote nodes and payment orchestration | All ZDN use |
| `ironwood-wallet` | Unsandboxed local key storage/signing backend, Common 3.0.0 | Optional ZDN CLI payments only |

Neither installation launches a node, creates AWS resources, generates proofs
or makes payments. AWS operation still costs money. Experimental custom Testnet
only: no real funds, Mainnet or production AWS account. Wallet files/backups are
plaintext secrets. Installing a backend does not register or authorize it.

**Preview 4 provides no macOS executable download.** Build locally from reviewed
source. Preview 2 browser downloads failed Gatekeeper because they were not
Developer ID signed/notarized; they are not the current installation path. Do
not strip quarantine, override Gatekeeper, re-sign downloaded files or change
security settings. If the OS blocks a locally built executable, stop and
investigate; these instructions do not authorize a bypass. The paid publisher
[signing runbook](macos-release.md) is separate and unnecessary for this path.

## Choose your source and trust boundary

The canonical public repository is <https://github.com/jonwalch/zdn>. No private
checkout or history is needed. The formulae in its `Formula/` directory pin the
Preview 4 release inputs, **not** moving `main` or a private Git URL. These
instructions require the `v0.1.0-preview.4` assets to be published first:

| Component | Archive / original revision | SHA-256 |
| --- | --- | --- |
| Controller | `zdn-product-source-3c136fb.tar.gz` / `3c136fbfd2e50bac43d889b53ea0ef341ef40848` | `efe868012fed69fa27814f9dcfe18ee536d9bd075044ba23a2bd3482559a4347` |
| Wallet | `ironwood-wallet-source-preview.4.tar.gz` / `190661784574e13925f99f8bd1c77491db9fa9b5` | `c4f5dc330b81d43943f6d0b2526e8c0a4d7e4fe2ac2d7422dfc63e20762faf62` |

Keep `zdn-required-notices-preview.4.tar.gz` (SHA-256
`d39883fb1b4a6a84c4a128541dddcb63f3cdf861d04fbf3772c88a15a7f07b3d`)
and `ironwood-wallet-required-notices-preview.4.tar.gz` (SHA-256
`bcb80e704aac614e4526807dff344aa56199aebffdd941e8312c3dd5e3fd4fa6`)
with the corresponding sources. These notice wrappers retain historical
supplements and record current applicability, not executable equivalence or
live-network qualification. Preview 4 wallet source is new, not the unchanged
Preview 2/3 wallet archive.

Verify these pins through a channel you trust before building. Checksums detect
changed bytes, not publisher identity, safety or legal clearance. Cargo builds
execute dependency build scripts locally. You trust the source, formula, tap
maintainer, GitHub delivery, Rust toolchain, registry dependencies and Homebrew
when you use it. **This is a publisher-owned tap, not Homebrew-core review or
endorsement.** A future tap update can change formula code and source pins;
review it before upgrading. There are no ZDN/wallet bottles in this tap.
Homebrew may use bottles for build dependencies such as Rust, and can install
or upgrade their dependency closure (including LLVM and native libraries).

The controller needs Rust 1.97 or newer. Manual builds below use the native-test
toolchain **1.97.1**, with `--locked`. The wallet is its own edition-2024 workspace
with its own lockfile and exact `zakura-* =3.0.0` registry dependencies. Its
archive includes `BUILDING.md`, `SOURCE-PROVENANCE.json`, original attribution,
MIT/Apache-2.0 licenses, tests and manifests; there are no path dependencies.
Registry dependencies are **not vendored**. SQLite (both programs) and secp256k1
(wallet) compile bundled native code. No node checkout, Docker, protobuf compiler
or research workspace is required. Do not run proof examples to install a wallet.

## Option A: source-building Homebrew tap

Install Homebrew from its official instructions and native compiler tools first.
On Apple Silicon, use `/opt/homebrew/bin/brew`, not an older Intel Homebrew in
`/usr/local`. The commands below assume native `brew` is on `PATH`; confirm:

```sh
command -v brew
brew --version
brew --prefix
```

Tap the **explicit public URL** (this repository is not named `homebrew-zdn`),
inspect both formulae, then install only what you need:

```sh
brew tap jonwalch/zdn https://github.com/jonwalch/zdn.git
brew cat jonwalch/zdn/zdn
brew cat jonwalch/zdn/ironwood-wallet
brew install --build-from-source jonwalch/zdn/zdn
# Optional, for CLI payments:
brew install --build-from-source jonwalch/zdn/ironwood-wallet
brew test jonwalch/zdn/zdn
brew test jonwalch/zdn/ironwood-wallet
```

Skip the wallet install/test for management-only use. No `sudo` is needed in a
normally owned Homebrew prefix. Formulae use Homebrew's `rust` build dependency
and locked Cargo installs; its compiler version can differ from manual 1.97.1.
Require Rust >=1.97; if your Homebrew Rust is older, use the manual path rather
than editing the lockfile or minimum Rust version. Build time/disk use depend on
your machine; this is not a download of the released executable.

`brew --prefix zdn` and `brew --prefix ironwood-wallet` identify installed kegs;
`$(brew --prefix)/bin` contains command links. Original licenses/READMEs are under
each keg's `share/doc`, and lockfiles/toolchain plus required release notices
under `share/zdn` or `share/ironwood-wallet`. Wallet provenance is retained there
too. Formulae fetch notices as separately hash-pinned resources.

Select the installed controller:

```sh
ZDN="$(brew --prefix zdn)/bin/zdn"
```

**Optional wallet only:** if you installed it, choose the physical, versioned
executable, **not** the Homebrew `bin` or `opt` symlink (ZDN intentionally refuses
symlink backends). Management-only users skip this block:

```sh
IW="$(cd "$(brew --prefix ironwood-wallet)/bin" && pwd -P)/ironwood-wallet"
test -f "$IW" && test ! -L "$IW" && test -x "$IW"
```

If these formulae are not yet on public `main`, the tap commands cannot find
them. To test a reviewed local public checkout before publication, without
altering an existing tap or controller, use a distinct local tap:

```sh
brew tap-new local/zdn-source
cp Formula/zdn.rb Formula/ironwood-wallet.rb "$(brew --repository local/zdn-source)/Formula/"
brew install --build-from-source local/zdn-source/zdn
brew install --build-from-source local/zdn-source/ironwood-wallet
brew test local/zdn-source/zdn
brew test local/zdn-source/ironwood-wallet
```

Run from the public checkout root; inspect the copies before installing. Do not
install both tap variants simultaneously or force-overwrite an existing command.

## Option B: manual pinned-source installation (no Homebrew)

Install native C/compiler/linker tools: Xcode Command Line Tools on macOS, or
your distribution's C compiler/build tools on Linux (for example `build-essential`
on Debian/Ubuntu). Install Rust via its official channel, then select the exact
toolchain. Git is needed for the later network walkthrough; `curl`, `tar`, and
`shasum` (Perl Digest::SHA; Linux can instead use `sha256sum`) are used below.
No AWS tools or credentials are needed just to build and run offline commands.

Use a new directory outside any node/research checkout. These commands change
only that directory, your Rust toolchain cache, and the selected install prefix:

```sh
set -eu
umask 077
mkdir zdn-source-install
cd zdn-source-install
rustup toolchain install 1.97.1 --profile minimal
rustc +1.97.1 --version
cargo +1.97.1 --version
BASE=https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.4
curl --fail --location --output zdn-product-source-3c136fb.tar.gz "$BASE/zdn-product-source-3c136fb.tar.gz"
curl --fail --location --output zdn-required-notices-preview.4.tar.gz "$BASE/zdn-required-notices-preview.4.tar.gz"
printf '%s\n' \
  'efe868012fed69fa27814f9dcfe18ee536d9bd075044ba23a2bd3482559a4347  zdn-product-source-3c136fb.tar.gz' \
  'd39883fb1b4a6a84c4a128541dddcb63f3cdf861d04fbf3772c88a15a7f07b3d  zdn-required-notices-preview.4.tar.gz' > controller.SHA256SUMS
case "$(uname -s)" in
  Darwin) shasum -a 256 -c controller.SHA256SUMS ;;
  Linux) sha256sum -c controller.SHA256SUMS ;;
  *) echo 'This guide covers macOS and Linux' >&2; exit 1 ;;
esac
mkdir controller controller-notices
# Controller archive has files at its root: do NOT --strip-components=1.
tar -xzf zdn-product-source-3c136fb.tar.gz -C controller
tar -xzf zdn-required-notices-preview.4.tar.gz -C controller-notices
PREFIX="$HOME/.local"
cargo +1.97.1 install --locked --path controller --root "$PREFIX" --bin zdn
ZDN="$PREFIX/bin/zdn"
export PATH="$PREFIX/bin:$PATH"
```

Cargo refuses an existing installation rather than silently replacing it; do
not add `--force` without reviewing what you would replace. Keep the entire
source-install directory (archives, lockfiles, source attribution and notices)
with your installation records. Add the PATH setting to your own shell profile
if desired. A current public Git checkout can instead be built with
`cargo +1.97.1 install --locked --path . --root "$PREFIX" --bin zdn`; record
`git rev-parse HEAD` and `git status --short`. That builds the checkout, not
necessarily the Preview 4 pin. Never copy private history into a public checkout.

For optional CLI payments, continue in the same source-install directory:

```sh
curl --fail --location --output ironwood-wallet-source-preview.4.tar.gz "$BASE/ironwood-wallet-source-preview.4.tar.gz"
curl --fail --location --output ironwood-wallet-required-notices-preview.4.tar.gz "$BASE/ironwood-wallet-required-notices-preview.4.tar.gz"
printf '%s\n' \
  'c4f5dc330b81d43943f6d0b2526e8c0a4d7e4fe2ac2d7422dfc63e20762faf62  ironwood-wallet-source-preview.4.tar.gz' \
  'bcb80e704aac614e4526807dff344aa56199aebffdd941e8312c3dd5e3fd4fa6  ironwood-wallet-required-notices-preview.4.tar.gz' > wallet.SHA256SUMS
case "$(uname -s)" in
  Darwin) shasum -a 256 -c wallet.SHA256SUMS ;;
  Linux) sha256sum -c wallet.SHA256SUMS ;;
  *) echo 'This guide covers macOS and Linux' >&2; exit 1 ;;
esac
mkdir wallet wallet-notices
tar -xzf ironwood-wallet-source-preview.4.tar.gz -C wallet
tar -xzf ironwood-wallet-required-notices-preview.4.tar.gz -C wallet-notices
# Preview 4 archive has files at its root, with no wrapper directory.
WALLET_SOURCE=wallet
cargo +1.97.1 install --locked \
  --path "$WALLET_SOURCE/experiments/ironwood-wallet" --root "$PREFIX" --bin ironwood-wallet
IW="$(cd "$PREFIX/bin" && pwd -P)/ironwood-wallet"
test -f "$IW" && test ! -L "$IW" && test -x "$IW"
```

No claim of byte-reproducibility, full license clearance, or binary equivalence
to the release is made. Keep the original wallet README and provenance; historical
research repository names are attribution, not dependencies or access requirements.
Historical binary/toolchain provenance in the original notices supplements
describes Preview 2, not the hashes or compiler of your new local build. The
controller wrapper's `APPLICABILITY.json` records the Preview 4 dependency-closure
applicability; it does not turn historical binary evidence into new build evidence.

## Verify installation and explicitly select the wallet

For either path, record the compiler, source/lockfile hashes, executable paths
and executable SHA-256. Homebrew users can record `brew info --json=v2` for each
fully qualified formula and `"$(brew --prefix rust)/bin/rustc" --version`.
All users run these controller checks; they do not contact AWS:

```sh
"$ZDN" --version
"$ZDN" reference > command-reference.txt
"$ZDN" reference --schema > command-schema.json
```

Require `zdn 0.1.0` and reference `apiVersion` `zdn-command-reference/v1alpha1`.

### Optional wallet: verify and register

**Management-only users skip this section** and continue at
[first-network setup](#continue-to-first-network-setup). Only run the following
if you installed the wallet and set its physical `IW` path above. These checks
do not create wallet keys or contact AWS; there is no wallet `--version`:

```sh
"$IW" capabilities
case "$(uname -s)" in
  Darwin) IW_SHA256=$(shasum -a 256 "$IW" | awk '{print $1}') ;;
  Linux) IW_SHA256=$(sha256sum "$IW" | awk '{print $1}') ;;
esac
```

Require wallet `schema_version` 1 and capabilities `ironwood-wallet-state/v2`,
`ironwood-wallet-state-observation/v2`, `ironwood-wallet-snapshot-payment/v2`.
For transparent payments also require `transparent-wallet-payments/v1` and
`transparent-wallet-state-observation/v1`; older backends refuse without fallback.
The crate version alone does not identify either build. The locally computed
hash identifies **your reviewed local build**, not an arbitrary trusted download.

Once you trust those source/build inputs, configure the backend explicitly.
This writes local settings only; it does not create keys or contact AWS:

```sh
"$ZDN" wallet backend set --backend "$IW" --backend-sha256 "$IW_SHA256"
```

Use your intended private wallet root, or put `--wallet-dir /absolute/private/root`
after `wallet` and before `backend` to isolate a smoke test. Keep the same root
for later commands. Every backend use checks its bytes again. Homebrew upgrades
change the versioned path/hash; review and re-register deliberately, never edit
saved settings to bypass checks. Do not force-link a backend to evade pinning.

### Continue to first-network setup

Next, follow [first-network setup](preview-start.md#source-installed-controller)
for Git, AWS CLI v2, Session Manager, verified node source, chain inputs, and the
**separate Linux x86-64 host helper on a Mac**. A native Mac controller cannot be
the remote Linux helper. Managed tools (`zdn deps install`) are separate downloads.
On Mac, use that guide's short private physical `TMPDIR` and UNIX-socket preflight.
Read [agent instructions](automation.md#agent-operating-checklist) before delegating
operation. Offline installation checks are not live payment, browser-binary,
cross-platform or clean-machine qualification.

For contributor checks beyond installation, use [testing](testing.md). On a Mac
the ordinary suite's generated-build fixture needs modern Bash ahead of Apple's
Bash 3.2 and GNU coreutils on PATH. Those are test prerequisites, not a reason
to run node builds or proof-producing examples during installation.

### Preview 4 source-build checks (2026-10-30)

The exact controller source pin above passed native Apple Silicon locked/offline
release build, formatting, all-target Clippy with denied warnings and the full
ordinary suite: **1,251 passed, 0 failed, 1 ignored**. The wallet source archive's
35 files/modes independently reconstructed its declared Git tree. Its native
release build, formatting, Clippy and selected proof-free suite passed:
**33 passed, 0 failed, 2 proof tests ignored, 3 capacity/history tests skipped**.
Native capabilities/help/refusal controls and Ruby syntax for both formulae passed.
No Homebrew installation, tap upgrade, signing/notarization, browser-download,
node build, proof generation or cloud run was performed for these native checks.
These are current source-build checks, not inherited historical installation
or new-binary live qualification. See [release check details](transparent-payments-validation.md#preview-4-release-checks).

### Checked installation scope (2026-10-28)

**Historical Preview 2/3 inputs only, not Preview 4 qualification.** The updated
Preview 4 formulae and source pins have not inherited these Homebrew, native
installation or cloud results. Check the new builds separately; see the
[bounded transparent-payment evidence](transparent-payments-validation.md)
for the exact later AWS candidate and its release-binary qualification boundary.

The exact Preview 3 controller source archive installed successfully on native
Apple Silicon macOS 27.0.1 with `cargo +1.97.1 install --locked`. Every source
file and executable mode matched the pinned public Git tree. The Linux locked
release build, executable schema/capabilities, source capture and chain-byte
checks also passed.

Those Preview 3 checks used `zdn-product-source-fe2ccf3.tar.gz`, revision
`fe2ccf325b57f8538973c31bcf26322a416eae55`, SHA-256
`5e7c167e690d42b1f16d46716cf6351e7a8d3a9cdbce59b3746ac5c98c272737`;
the existing wallet was `ironwood-wallet-source-70ccc7f.tar.gz`, revision
`70ccc7f45ef9ecdea46151719b82b356b48e2d76`, SHA-256
`5fadd8187145d577d98a265dd50279483390e67b6617e50b1cabbb097d30a4d2`.
These are historical identities, not alternative current installation pins.

The subsequent [bounded native journey](preview.md#verified-native-journey-2026-10-28)
used that same source-installed controller and the existing pinned source-built
wallet. One source build/node, normal reward maturity, three confirmed payments,
original-UUID reopen, coherent backup and independently audited cleanup passed.
This execution evidence is separate from installation checks and does not imply
full beta, general Mac support or browser-download qualification.

The earlier checks below cover Preview 2 installation inputs, not the updated
Preview 4 controller/wallet/formula versions. The wallet source, lockfile and
notice bytes were unchanged between Preview 2 and Preview 3, not Preview 4:

- Linux x86-64: both pinned archives installed with Rust/Cargo 1.97.1 and
  `cargo install --locked`. Installed schema/capabilities, backend registration,
  wrong-hash and symlink rejection passed. The documented source-installed
  input downloads/checksums, node-source Git identity and chain byte checks passed.
- Apple Silicon macOS 27.0.1 / Xcode 27: both formulae installed from source with
  native Homebrew 7.0.4 and its Rust/Cargo **1.99.1**, not manual 1.97.1. Both
  `brew test` and final `brew style` passed in a disposable local tap. Installed
  offline consumer checks, physical Cellar-path registration, wrong-hash/symlink
  rejection and retained notices/provenance passed with Gatekeeper enabled.

These were existing developer machines/environments, not clean-machine,
Homebrew-on-Linux, Intel Mac, live payment or browser-download qualification.
No cloud, node build, proof generation or performance workload was run as part
of those earlier installation checks.
Public tap fetching still depends on these formulae being published to public
`main`; local-tap testing does not publish them or modify any existing release.

## Update or remove the local programs

Before updating, preserve source/notices/build records and back up wallet state
with all writers stopped. Inspect new formulae/pins; `brew upgrade --build-from-source
jonwalch/zdn/zdn` (and separately `jonwalch/zdn/ironwood-wallet`) compiles new
versions. Re-run offline checks and explicitly register the reviewed wallet path
and hash again. Homebrew cleanup can remove old kegs, so do not depend on an old
Cellar path indefinitely. Do not mix manual and Homebrew executables on PATH.

`brew uninstall jonwalch/zdn/zdn` and, separately,
`brew uninstall jonwalch/zdn/ironwood-wallet` remove Homebrew programs, not ZDN
state or AWS resources. For a manual Cargo install use `cargo uninstall --root
"$PREFIX" zdn` / `cargo uninstall --root "$PREFIX" ironwood-wallet` after checking
that prefix. Neither route backs up wallets, stops a network or ends AWS billing.
Keep recovery records; use [network/team removal](removal.md) for AWS cleanup.
