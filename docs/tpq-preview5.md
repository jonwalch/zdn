# ZDN Preview 5 — Linux TPQ experimental preview

Preview 5 is the opt-in **tpq-linux-x86_64** companion-tool distribution.
Use it only with disposable funds in a dedicated AWS development account.
It is not Mainnet, public Testnet, production-wallet or full-beta software.
Ordinary Preview 4 downloads and Mac source instructions remain unchanged.
No Mac/ARM TPQ external execution is qualified by this release.

## Downloads and trust

Get the separate assets from
[v0.1.0-preview.5](https://github.com/jonwalch/zdn/releases/tag/v0.1.0-preview.5).
Start with the release asset **START-TPQ.md**, which gives the complete download
list, verification commands, extraction layout and link to the bundled walkthrough.
The profile contains all 13 required roles plus its distribution index/checksums.
No prebuilt node image is required; ZDN builds the pinned source through CodeBuild.
Linux tools require x86-64 and GLIBC 2.34 or later.

| Integrity file | SHA256 |
| --- | --- |
| `distribution.json` | `06fe647e6e85a6c1af7e7e363b7af522c59a0c072ef54811463b9512a42b772d` |
| `SHA256SUMS.tpq-linux-x86_64` | `bffe2318ed74c44eac8ef4ccc571656da2c3bf553e47bdce7f617093fe3fe701` |
| `build-manifest.json` / adapter selection | `1afeb0f031d5cb0b8e08c511725c9543b722e707c40fb6610001402b7f677581` |

**Unsigned preview:** independently authenticate the index/checksum pins through
a trusted release channel before checking all files. Co-downloaded checksums do
not authenticate a publisher. Explicitly trust the reviewed local tools and adapter;
do not bypass OS protections or use `--ignore-missing`. No publisher signature,
full SBOM, reproducible/hermetic build or general legal clearance is claimed.
The included notices inventory Linux operator-tool normal/build dependencies,
not the complete node-image operating-system dependency closure. Keep sources,
original attribution and notices with the tools.

## Exact source and executable scope

The corresponding source is ZDN
`be908b9dad0a7ebafd4eb2ca204a52892026ab30` and TPQ
`b4670732f34011771da0408508356a3590f5df79`. The complete TPQ source archive
retains its exact Git identity in a minimal remote-free shallow repository.
The controller source archive contains the exact tracked files of its revision.
The release tag may include later documentation; it does not change build provenance.
TPQ source is also published through [PR #21](https://github.com/jonwalch/zcash-tpq/pull/21),
not pushed to TPQ main. Public ZDN ancestry is used; no private zdn-internal
history, research history, private qualification bundle or operational authority
belongs in this distribution.

| Executable | SHA256 |
| --- | --- |
| `zdn` | `15cf6cd4d3a27f688ccaf2aebec55d5e9d607b65c68f032b1c5ab33200c9a9f6` |
| `zdn-tpq-adapter` | `7120071d2a6a40f4b2cf398af47366b23adbf3008e6d994f8cc0f234a9bf6eda` |
| `zdn-tpq-import` | `24821e7382fd16779187b0ba2fc6d254ed90106b187dcc45f1830142cf55afe1` |
| `tpq-devnet` | `131aa9d1396aadc3a737bf8168110cd6d859aedbe97f481ea3c3305617be3250` |
| `pq-wallet` | `151cd0a57991445bce524f4fcbe5e2fd3e450ff9ec64051a6b60e2bd4b2fb1fe` |

All five are the exact November 2 R4 rehearsed executables; none was rebuilt or
post-processed for publication. The adapter/importer remain signing-free separate
builds; local wallet/devnet tools retain signing authority. Node hosts get public
verification inputs, not participant wallet keys. The unchanged build manifest
records compilers, features, locks, ABI and source identities. Its preparation-time
limits and bundled guides' R8-only/pending-rehearsal status text are historical;
the R4 result below supersedes those status statements, not the operational steps.
The distribution schema's `unqualified` field deliberately does not assert full
beta or publisher authentication. The new START document and release identity
have new checksum pins; the other 12 role assets match the R4 candidate exactly.

## Completed testing

On November 2, one fresh bounded **delivered-tool** AWS rehearsal passed without
the private research payment driver, a product patch, deadline renewal or weakened
gate. It used one source CodeBuild and two private `m7a.large` AL2023 hosts.

- Fresh public preparation/import/CoreTrust, source-to-image deployment and
  initial ordinary health with production active.
- One seed funding and three PQ payments: Alice to Bob v5 1,000,000 zat, Bob to
  Alice v6 400,000 zat, and restored Alice to Bob v6 100,000 zat. Each PQ payment
  used one experimental SLH input and paid 21,600 zat; that is not a universal fee.
- Coherent monitor/known wallet snapshots, monitor authority refusals, retirement
  of the old allocator before known restore, extended backup and restored spending.
- One retained node-only restart per node, bound native rules/history/tip readiness
  with production intentionally stopped, and successful real wallet requests through
  the original gateways with unchanged process identities. Initial health was not weakened.
- **38 fresh final controls**: on each node, two bracketing tips, four transactions,
  four canonical blocks and nine distinct outpoints. Exact bytes, inclusion,
  spent/unspent lineage outputs and wallet coin sets matched. Five generated blocks
  ended at height 106. Alice held **2,256,800**, Bob **678,400 zat**; their sum plus
  three 21,600-zat fees equals the 3,000,000-zat funding. The original-inventory
  monitor held 400,000 zat; extended-monitor parity is not claimed.

The wallet journey took **2,508.211 seconds / 41.804 minutes** from its immutable
origin, including connection setup; n=1, p50=p95=p99 for that duration. Across
116 complete controls (232 subprocesses), nearest-rank latency p50/p95/p99 was
**15.804 / 17.180 / 19.006 seconds**, max 21.355 seconds. Fresh a/b/a maximum-sample
remaining-work admission passed within all original deadlines, without the obsolete
15-second threshold or extra polling. These observations are not a production SLO.

Selected supporting subcases: **REL-01/02/03/05, SRC-03/DEP-02, PAY-01/02,
WAL-08/JRN-06 and CLN-01/03**, against beta plan **v1.0 / 2026-10-23**,
SHA256 `20bc7e52be2df2d78706d5e4c453bfa91e42feefcad83d550c5a1abc31a499d2`.
This is not whole-case closure. The frozen private evidence index covers 3,979
records, SHA256 `55beeda49b6b4388badb8f8c2bac70aa0f1512539e60754e6ce8448149da35ac`;
final summary SHA256 `2e7188b1521aab18f6fd0f66888afce052ad34a9706c76afc08fa43bce92bcf1`.
All 52 original execution pins and five observer pins matched after cleanup.
Raw operational evidence and secrets are not release assets.

## Preview 5 errata and known issues

Added after release; the release assets are unchanged. Apply these corrections
when following the bundled START-TPQ.md and walkthrough.

**Two-hour hard limit.** The template's `lifetimeSeconds: 7200` is Preview 5's
maximum. It starts when `devnet up` starts the producer and is never renewed.
After it ends no block can be produced, so funding and payments cannot confirm;
the only way on is destroy and a new render/launch (a new billed build). Create
and back up both wallets and their receivers before `devnet up`: those steps
need only the local `wallet-profile.json`. Recorded rehearsals used 42 to 56
minutes. Later controllers accept up to 21600 seconds; Preview 5 refuses that.

**Cohort name.** 1 to 30 letters, digits or `_`; no hyphens or reserved names
(example `tpq_trial_1`). A refused `tpq-devnet prepare` leaves its two output
directories behind: remove them, or choose new paths, before retrying.

**Health after stopping the producer.** `zdn devnet health` reports not ready
once you run `stop-producer`. Run it before that. Afterwards, readiness is the
saved control results: fresh `tip.json` on both nodes with the same height and
hash, the `restart-node` result, and `gateway-identity.json` on node-1.

**Shell.** Do not paste `set -eu` into your interactive shell: a failing command
closes it and loses every variable. Run checks in a `( set -eu; … )` subshell
and keep values in a private file you load in each terminal. Under zsh, use
`[ "$(umask)" = 0077 ] || [ "$(umask)" = 077 ]` for the umask check.

**Concrete Preview 5 values.** With everything extracted in `$DOWNLOADS`:
`ZDN=$DOWNLOADS/zdn`, `HOST_ADAPTER=$DOWNLOADS/zdn-tpq-adapter`,
`IMPORT=$DOWNLOADS/zdn-tpq-import`, `DEVNET=$DOWNLOADS/tpq-devnet`,
`WALLET=$DOWNLOADS/pq-wallet`, `NODE_SOURCE=$DOWNLOADS/node-source`,
`STARTER=$DOWNLOADS/tpq/docs/slh-dsa-b128s/zdn-preview` (note the `tpq/`
prefix), `NODE_REV` and `TPQ_REV` both
`b4670732f34011771da0408508356a3590f5df79`, and `ADAPTER_SELECTION_SHA256`
`1afeb0f031d5cb0b8e08c511725c9543b722e707c40fb6610001402b7f677581`.

**Where printed values come from.**
- `NETWORK`: `jq -r .networkId` on the `devnet render` output.
- Inventory fingerprint: `pq-wallet --json export …` prints `inventory_fingerprint`.
- Funding digest: `transaction_sha256` in the funding review file, after you
  check its amount, fee, change, recipient script and expiry fields.
- Proposal ID: `proposal_id` in the `review` output, after checking its
  receiver, amount, fee and change.
- Receipt fingerprint: `pq-wallet --json snapshot-save …` prints `receipt_fingerprint`.
- `TRUST_PRINCIPAL`: an IAM user ARN, or for SSO/assumed roles the IAM role ARN
  with its path (`aws iam get-role --role-name NAME --query Role.Arn`), not the
  `sts … assumed-role` ARN.
- The YAML `profile` field is the local ZDN profile (`$ZDN_PROFILE`, normally
  `default`), not your AWS profile.

**Zone.** The `small` preset is `m7a.large`. Choose `ZONE` from
`aws ec2 describe-instance-type-offerings --location-type availability-zone
--filters Name=instance-type,Values=m7a.large --region "$REGION"`.

**Later `produce` controls** run on `--node node-1`; node-2 refuses them.

**What "independently verify" means here.** Release pins: compare with this
document at tag `v0.1.0-preview.5`, a second view from the same publisher, not
a signature. Inventory fingerprints: in a solo test the value `export` printed
is the comparison; with another participant, confirm it with them separately.
Funding and payment approvals: your review of the displayed fields is the
check; the digest or ID only pins the reviewed bytes.

**Known controller issues, fixed on `main` after release** (commit `335d9e1`):
- Interrupting `devnet up` (Ctrl-C) while it seeds the chain can still submit
  seed blocks and mark bootstrap complete. Resume with the same saved network
  ID and `--reconcile`; never re-render.
- An image update can stall with node-1's gateway down if the production
  lifetime expires mid-update. The walkthrough does not run image updates.

**Reward address.** The walkthrough needs a classical Testnet t-address whose
key you control, and nothing in this distribution creates one. Use a
classical Testnet wallet you already trust. Preview 5 checks the full address
format only after the billed build.

## Cleanup, costs and limits

All five product teardown/removal operations exited zero. Both exact original
encrypted chain disks were independently available/unattached after retain teardown
and before data deletion. Staged/final independent audits passed **233/232 observations**,
preserving **61 protected keys across 17 enabled regions**, with zero active instances.
The original managed connection closed cleanly and all five orb run services stopped.
The run-owned KMS key is PendingDeletion until **2026-12-02 03:07:23.046 UTC**;
this is not physical deletion, STS invalidation, billing closure or account-wide
absence of every possible resource. The $30 envelope/$10 cleanup reserve were
planning bounds, not a hard cap or measured actual bill.

AWS builds, NAT, compute and storage cost money. Test producer lifetime and work
windows are explicit configuration, not innate ZDN expiry or spending caps.
Keep private files mode-restricted in every shell and retain original IDs/receipts
for uncertain effects. Use product lifecycle operations and independent scoped
audits; successful CLI removal alone is not proof of resource/billing closure.

Full beta, independent cryptographic certification, lost-reply/signing-interruption
matrices, controller handoff, image update, host reboot, reorg, multisig, maximum
context/performance, additional platforms and opposite-peer AWS wallet submission
remain unqualified. Same-orb backup checks do not prove offsite disaster recovery.
Controller optimization is deferred, not a preview launch threshold. No additional
AWS run, node build, deployment or package-registry publication is part of this release.
