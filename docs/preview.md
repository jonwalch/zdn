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
- **Apple Silicon Mac:** native developer/offline checks pass on macOS 27.0.1,
  but **browser-download installation is blocked**. Gatekeeper rejected both the
  quarantined controller and wallet downloaded through Chrome. Their bytes match
  the published downloads and their ad-hoc signatures are intact; neither is
  Developer ID signed or notarized. Unquarantined developer execution is not
  evidence that ordinary downloaded files work.
  Current Mac AWS/payment qualification is not complete. Do not remove
  quarantine, re-sign downloads or bypass Gatekeeper; use the checked Linux
  path for now.
- **Unsigned distribution:** checksums identify bytes, not publisher identity,
  artifact safety or legal clearance. Verify pins through a trusted channel.
  No reproducible-build or general platform-support claim is made.

ZDN trusts the selected validating node and the separately pinned, unsandboxed
wallet executable. It is not a consensus light client or production wallet.
Keys and complete wallet stores remain local and contain plaintext secrets.
Normal scheduled mining and reward maturity are required for payments; an open
RPC port or capability response is not a payment test.

## Source identities and notices

Preview 2 runtime binaries were built from product revision
`e4dbcae3367bdc440fa9ec966b6d82663cb3a5ee`. The product-source archive identifies
that exact build; maintained repository documentation can be newer. The internal
`0.1.0` version alone is not a binary pin. Use the exact hashes and source
identities in `distribution.json` and the release notes.

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
