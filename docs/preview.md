# Public preview: scope and installation status

ZDN creates private, disposable Zcash test networks in your AWS account.
Use the [installation walkthrough](preview-start.md) to verify downloads, set up
an account, launch one node and remove its resources. Downloads and their exact
pins are on the [public releases page](https://github.com/jonwalch/zdn/releases).

This preview is for trusted developers in a dedicated development AWS account.
Do not use real funds, production accounts or untrusted co-tenants. AWS resources
cost money, including retained disks and storage after network removal.

## Choose a workflow

| Goal | Start here |
| --- | --- |
| Install local programs without paid signing | [Manual and Homebrew source builds](install-source.md) |
| Start and remove a network | [Installation and first network](preview-start.md) |
| Connect an application or another participant | [Private connections](connections.md) |
| Fund, send and recover CLI payments | [Wallet walkthrough](wallet.md#first-payment-alice-and-bob) |
| Operate ZDN with an agent | [Automation checklist](automation.md#agent-operating-checklist) |
| Find an advanced contract | [Documentation index](README.md) |

Management profiles include the controller, Linux helper, node source/map, chain
inputs and required source/notices. Payment profiles additionally include the
separate Ironwood wallet program and its source/notices. Management does not
require a wallet download. Vizor and Zodl have not been qualified with ZDN.

## Platform and trust limits

- **Linux x86-64:** executable checks cover GLIBC requirements through 2.34 and
  the specific one-node workflow identified in the release notes. This is not
  universal Linux distribution or clean-machine support.
- **Apple Silicon Mac:** [build locally from source](install-source.md), manually
  or with the publisher Homebrew tap. Preview 3 distributes no Mac executables or
  Mac executable-download profiles. Earlier Preview 2 browser downloads failed
  Gatekeeper assessment and were withdrawn, not made usable by changing security
  settings. Native source installation/offline checks pass on macOS 27.0.1;
  candidate-specific AWS/payment coverage is recorded in the release notes.
  No Intel Mac, clean-machine or universal macOS support is claimed. Never remove
  quarantine, re-sign downloaded files or bypass Gatekeeper to proceed.
- **Unsigned distribution:** checksums identify bytes, not publisher identity,
  artifact safety or legal clearance. Verify pins through a trusted channel.
  No reproducible-build or general platform-support claim is made.

ZDN trusts the selected validating node and the separately pinned, unsandboxed
wallet executable. It is not a consensus light client or production wallet.
Keys and complete wallet stores remain local and contain plaintext secrets.
Normal scheduled mining and reward maturity are required for payments; an open
RPC port or capability response is not a payment test.

## Verified native journey (2026-10-28)

The exact Preview 3 source-installed Apple Silicon controller, separately pinned
Linux helper and existing source-built Ironwood wallet completed one source build,
one healthy private node, normal 25-second/100-block maturity and three confirmed
payments. Amounts, fees, canonical inclusion and final balances passed; the original
payment UUID reopened unchanged, a coherent 38-file backup passed, and retained
disk deletion and independent 200/199-observation cleanup audits passed with the
complete protected account baseline unchanged. The owned KMS key is scheduled
for deletion, not physically deleted.

See the [public qualification summary](preview3-native-validation.md)
for exact component identities, selected subcases, earlier failures and limits.
This is not full beta, general Mac support, signing/notarization, browser-download,
lost-dispatch, hostile rollback or reorg qualification. Published assets are
unchanged; no private operational evidence or wallet data is distributed.

## Source identities and notices

Preview 3 controller/helper and source installation use product revision
`fe2ccf325b57f8538973c31bcf26322a416eae55`. The product-source archive identifies
that exact build; maintained repository documentation can be newer. The internal
`0.1.0` version alone is not a binary pin. Use the exact hashes and source
identities in `distribution.json` and the release notes.

The standalone wallet remains source `70ccc7f45ef9ecdea46151719b82b356b48e2d76`
(Common 3.0.0). Its source, Linux executable and original wallet-notices download
are republished unchanged; local Mac builds have their own executable hashes.
The new controller-notices wrapper records applicability to the unchanged
manifests/lockfile and target dependency closures, retaining original supplements
and attribution without transferring their historical live claims.

The public node-source archive has its own Git identity and a source map of
included files, modes and hashes. Its historical research origin is revision
`f39268e2caa87acf3b78c228d4a41a0b95a35a1a`; the distributed projection is not
that commit. Public corresponding sources are supplied as release assets;
access to private development history is not an installation prerequisite.
Source changes do not inherit prior live qualification.

Keep all source, notice and recovery supplements required by your selected
profile. Original license texts and attribution are retained. Historical build
evidence inside immutable supplements is not current binary qualification.
The notices inventory selected Cargo dependency closures, not an exhaustive
native object/link map or legal opinion. Disclosed limitations include missing
original `enum-assoc` grant text, partial `zakura-assets` generated/dirty-source
attribution and separately scoped macOS SDK/toolchain rights. These limitations
remain unresolved; the notices describe their exact scope.

## External tools and ongoing costs

Install AWS CLI, the Session Manager plugin and Git separately. ZDN downloads
pinned managed Pulumi tools. Node source builds also download base images,
packages and crates: pinned source is not a hermetic/offline image build.

Deployment credentials can read and cancel other SSM commands in their region
unless externally restricted; see [AWS permission limits](aws-state.md#permissions-and-recovery).
Preserve original receipts and wallet backups. Follow [removal](removal.md)
through team cleanup, then independently check for remaining resources.
Scheduled KMS deletion is not immediate physical deletion, STS invalidation or
proof that billing has ended.
