# Public experimental preview

Public source and downloads: [jonwalch/zdn](https://github.com/jonwalch/zdn).
Start with the selected release's `START-NETWORK.md` and exact-profile checksums.
The maintained copy of the instructions is [here](preview-start.md). The public
repository is a clean source snapshot, not a publication of private product or
research history. Historical links into private research are attribution and
background, not installation prerequisites; corresponding public sources are
separate release assets.

Preview 2 distributes the controller/helper runtime built from product revision
`e4dbcae3367bdc440fa9ec966b6d82663cb3a5ee`, with newer distribution-only
documentation. Its product source archive preserves that exact build revision,
including its older documentation. The public repository's runtime Rust,
manifests and lockfile are unchanged from that build. The internal `--version`
remains `0.1.0`; it is not a sufficient binary pin. Use the exact SHA256 and
source identities in `distribution.json` and the release notes.

The node source is a separately identified parentless projection of research
revision `f39268e2caa87acf3b78c228d4a41a0b95a35a1a`. It retains build sources,
manifests, locks, required fixtures and original legal texts. Private historical
wallet-test results and AWS qualification programs/notes are omitted. This is a
new source identity, not the research commit. Its source map records every
included file, mode and hash. Source or capture changes do not inherit prior live
qualification. The release notes bind actual checks to the exact selected bytes.

## Intended audience and boundaries

Trusted developers, isolated custom Testnet, a dedicated development AWS
account, no real funds. This is not a production wallet or full-beta acceptance.
Use the one-node simplified-command walkthrough, preserve all local recovery
records and remove the disposable team when finished. Normal scheduled mining
and real reward maturity are required for payments. A ready node, parser check
or capability response alone is not a payment pass.

Management and payment profiles are different. Management does not require a
wallet download; CLI payments require the native Ironwood executable, matching
source and notices in addition to the controller/chain/node inputs. Signing keys
remain local, plaintext and private. The selected validating node and pinned
unsandboxed wallet executable are trusted. Vizor/Zodl remain untested.

Linux live evidence covers the specific controller/helper, wallet, source
capture, chain inputs and one-node workflow named in the release notes. Native
Mac checks are narrower and do not establish a downloaded Mac execution/trust
decision, a Mac AWS/payment journey or general platform support. Remaining Mac
qualification is agent-owned on an available native Mac environment, not deferred
to manual owner testing. It remains unqualified until actual results are recorded.
No quarantine removal, ad-hoc signing or
Gatekeeper bypass is an installation step. Unsigned checksums provide integrity,
not publisher authentication. No universal clean-machine or reproducible-build
claim is made.

## Notices and external prerequisites

Retain every source, notice and recovery supplement required by the selected
profile. Original license texts and attribution are retained, including upstream
author contact details and example paths. Historical inventory/build evidence
inside immutable supplements is not current binary qualification. The notices
document selected Cargo dependency closures, not an exhaustive native object/link
map or a legal opinion. Broader node inventory caveats include missing original
`enum-assoc` grant text and partial `zakura-assets` generated/dirty-source
attribution. macOS SDK/toolchain rights and external/runtime tools remain
separately scoped. These limitations are disclosed, not declared resolved.

AWS CLI, its Session Manager plugin and managed Pulumi are external prerequisites.
ZDN's pinned tool installer still uses network downloads. The source-build recipe
uses network base images/packages/crates; a byte-pinned source capture is not a
hermetic/offline image build. AWS can incur ongoing costs. Scoped resource
cleanup, scheduled KMS deletion and absence of resources in a bounded audit do
not prove immediate physical deletion, STS invalidation or billing closure.
