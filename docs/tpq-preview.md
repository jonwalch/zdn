# Linux TPQ experimental preview

This is the opt-in Linux x86-64 companion-tool path, not ordinary ZDN Preview 4.
Use the canonical TPQ walkthrough supplied as **START-TPQ.md** and retained at
`docs/slh-dsa-b128s/zdn.md` in the TPQ documentation/source archive. Its static
starter files live under `docs/slh-dsa-b128s/zdn-preview/`. Start there for the
complete preparation, import, source launch, wallet, recovery and cleanup journey.
Do not use the ordinary chain-manifest/bundle, Ironwood backend or `zdn wallet`,
`fund` and `send` commands for TPQ. No new Mac/ARM external execution is promised;
the [ordinary preview](preview-start.md) and Mac source path are unchanged.

## Download selection and trust

Choose **tpq-linux-x86_64** in the reviewed distribution index. No prospective
version/tag, asset filename or executable hash is fixed by this guide. Download
every profile asset and independently authenticate the checksum-list/index
digest through the release channel before verifying files. Co-downloaded
checksums do not authenticate a publisher. The preview can be unsigned; operator
trust remains explicit. Keep sources and notices with the tools. Never bypass
OS protections or use `--ignore-missing`.

The profile's required roles are:

- `controller-linux-x86_64`, `node-source`, `source-provenance`, `product-source`,
  `notices`, `instructions`;
- `tpq-adapter-linux-x86_64`, `tpq-import-linux-x86_64`,
  `tpq-devnet-linux-x86_64`, `tpq-wallet-linux-x86_64`, `tpq-notices`,
  `tpq-starter`, `tpq-build-manifest`.

There is no ordinary `chain-manifest`/`bundle` or Ironwood wallet role. The pinned
node source and its own Docker recipe are the minimum image path. A downloadable
node executable or prebuilt image is optional, not a prerequisite. Source
provenance must map the distributed Git revision to the actual upstream and
local source/inventory. A base commit alone cannot describe dirty-source builds.
Read the build manifest for each final executable's compiler/target/features,
byte count/hash, post-processing and actual tested ABI. Do not apply Preview 4's
binary hashes or R8's executable qualification to different bytes.

## Boundaries and prerequisites

Install Git, `jq`, `curl`, AWS CLI v2 >=2.37.4 and the native Session Manager
plugin (newer than 1.2.497.0). Use a trusted private absolute-path workspace and
a dedicated development AWS account. Keep one administrator-capable, non-root
source login and all original state/receipts through cleanup. Select a concrete
Amazon Linux 2023 x86-64 AMI and available zone in the chosen region. ZDN supplies
managed build tools; local Docker, Python and a private research harness are not
runtime requirements. AWS builds, NAT, hosts, storage and retained disks cost
money. Deadlines and height ceilings are not spending caps.

The controller owns cloud lifecycle and connections. The signing-free adapter
and importer validate/render public inputs; they are separate no-default-feature
`adapter` builds, never wallet-enabled feature-unified binaries. Local adapter
execution requires same-user trust. Host sandbox checks remain mandatory.
`tpq-devnet` and `pq-wallet` stay on the operator/participant machine with the
keys. Nodes own persistent native identities and private cookies, not wallet
authority. Do not distribute test funders or maintainers' operational directories.

Follow START-TPQ.md in order:

1. Verify/extract all assets and review source/build/provenance pins.
2. Prepare a **new** public seed (0..101) and separate **private** funder locally.
3. Import only the public chain/profile plus approved Linux adapter. Review the
   seven public slots and create explicit `CoreTrust` byte/hash/selection pins.
4. Bootstrap the disposable team through ZDN (real AWS mutation). Edit the
   two-node external template, render source capture locally, then explicitly
   launch its saved UUID (billed CodeBuild and deployment).
5. Require strict readiness. Prepare typed controls locally and execute only
   their reviewed saved IDs. Stop production, establish a stable tip, and use
   bounded production to reach funding readiness (NU7 102, SLH 103; maturity 100).
6. Keep `zdn connect` alive in terminal A. Use normal wallet commands in terminal
   B, numeric loopback sockets and explicit gateway transport, never `zdn exec`.
   Create/enroll/back up local wallets, independently review funding and v5/v6
   payment intents/approvals, then confirm with bounded controls and both peers.
7. Preserve original IDs/bytes on uncertainty. Save coherent snapshots, retire
   old allocators, restore trusted authority and make a new restored-wallet spend.
   Test retained node-only restarts and actual gateway continuity separately.
8. Stop writers/connections. Destroy retaining data, independently inspect retained
   original disks, then delete data and remove only the originally created team.
   Audit the exact scope independently; scheduled KMS deletion is not deletion.

For controller schemas and recovery, see [external controller](external-controller.md),
[connections](connections.md), [removal](removal.md) and [handoff](handoff.md).
Never substitute direct cloud writes for supported product lifecycle commands.

## Actual evidence, not release qualification

R8 on 2026-11-01 passed a 55.85-minute two-private-node AWS journey: one funding,
v5/v6/restored-v6 payments, retained node-only restart on each node and original
gateway continuity. Staged/final independent cleanup passed 229/228 observations,
preserving 57 protected keys and the baseline across 17 regions. KMS remained
PendingDeletion. This supports selected analog PAY-01, happy-path PAY-02, WAL-08,
JRN-06 and CLN-01/03 subcases of beta plan v1.0 / 2026-10-23, SHA-256
`20bc7e52be2df2d78706d5e4c453bfa91e42feefcad83d550c5a1abc31a499d2`.
It does not qualify future release bytes, clean-user REL-01/02/03/05 installation,
full beta, macOS TPQ, image updates, host reboot, handoff, lost-reply or other fault
injection. The separate qualification coordinator did not run. The finished
download-only walkthrough still needs its separately approved live rehearsal.
These instructions do not authorize builds, AWS, live wallets/nodes or publication.
