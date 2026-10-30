# Bounded transparent-payment qualification

On 2026-10-30, one approved AWS custom-Testnet journey passed six payments,
including genuine accepted-reply-loss recovery, node restart, a coherent wallet
restore and a fresh payment from the restored store. This is selected functional
evidence, not Mainnet, security, production-wallet or full beta qualification.

## What ran

The existing controller, separate wallet backend and real SSM/gateway path were
used with one private host/network, one source build, two proof-bearing
transactions and four proof-free transparent transactions. Canonical inclusions
were at heights 101–106:

| Height | Operation | Amount (zat) | Fee (zat) |
| --- | --- | ---: | ---: |
| 101 | Reward shielding into Ironwood | 100,000,000 | 15,000 |
| 102 | Ironwood → transparent Alice | 73,000,000 | 20,000 |
| 103 | Transparent Alice → Bob | 17,000,000 | 10,000 |
| 104 | Transparent Bob → Alice | 3,100,000 | 10,000 |
| 105 | Transparent Alice → Bob, accepted reply lost | 2,100,000 | 10,000 |
| 106 | Restored-store Bob → Alice | 700,000 | 10,000 |

Independent node observations checked exact raw transactions, canonical
inclusion, inputs, recipient/change scripts and integer fees. Six distinct
construction plans were used. The first two transactions alone contained
Ironwood bundles. Final transparent balances for Alice/Bob/bridge were
57,680,000 / 15,280,000 / 26,980,000 zat.

The lost-reply case recorded one accepted dispatch and preserved the original
operation, signed bytes and inputs without another submission. At height 105,
the backup validator verified 105 blocks; a quiesced complete wallet store was
copied to a fresh private path and the old store made unavailable. One node
service restart preserved the tip and Ironwood anchor. Restored observation of
the original payment made no `sendrawtransaction` call before the new payment.
The 99/100 maturity boundary, direct coinbase-spend refusal, pending balances and
same-wallet reservation refusal were also exercised.

## Cleanup and evidence boundaries

The runner exited zero after approximately 75 minutes. Product-managed cleanup
and independent 213-observation intermediate / 212-observation final audits
passed with the protected baseline unchanged. Owned compute, disks, networking,
build/cache/image/log, IAM/SSM and backend resources were removed or accounted
for. The run's backend KMS key was scheduled for deletion, not immediately
deleted. The approximately US$5 planning envelope is not actual billed cost or
an enforceable cap. Operational evidence and wallet data remain private.

The tested controller SHA-256 was
`83e406417583a2f9c7f930df057ee3852a48aa5c18ab5a4d81d1620b2e6c4f71`;
the tested backend SHA-256 was
`2b79c2e55a14935ca0ad6d31f5477afee64afa1ca7c40e5a40cd4c002be22dc5`.
All 66 frozen inputs remained unchanged. The completed private evidence manifest
binds 6,335 files with SHA-256
`ace4c272b101c21b4188368e5d954c4101c8ea8113738ffa53db6017d64cc899`.

Release builds have their own hashes and ordinary/offline checks; rebuilding or
path-remapping a binary does not give it the exact tested artifact's live
qualification. The new Linux adapter `describe` library boundary is not used by
ordinary payments or deployment. It has no CLI/lifecycle caller, and its
`compile`/`render` operations refuse before execution. Full TPQ integration is
not implemented or qualified.

P2SH live spending, multiple nodes, reorgs, broader interruption/concurrency and
incomplete-restore matrices, fresh release-binary cloud reruns and distribution
trust/clean-machine qualification remain separate gates. Mac source-build
checks are not browser-download Gatekeeper/notarization qualification. Existing
Ironwood defaults and coinbase shielding rules remain unchanged; see
[the wallet guide](wallet.md).

## Preview 4 release checks

The controller build/source pin is
`3c136fbfd2e50bac43d889b53ea0ef341ef40848`, with matching source archive;
the later release tag also includes maintained documentation. Linux
`env --default-signal=INT cargo test --locked -- --test-threads=2` passed
**1,444 tests, 0 failures, 1 ignored**, including the Linux-only adapter boundary
and its single-use compile-fail doc-test. Formatting and all-target Clippy with
`-D warnings` passed. One initial normal-parallel run failed an unchanged
reservation fixture (`reserved` expected, `prepared` observed); the exact focused
rerun and complete two-thread rerun passed. Its cause remains unverified, not
claimed repaired. Native Apple Silicon normal-parallel locked/offline testing
passed **1,251 tests, 0 failures, 1 ignored**; formatting, Clippy, release build
and executable no-cloud controls also passed. The adapter has no Mac target.

Wallet source identity `190661784574e13925f99f8bd1c77491db9fa9b5` was independently
checked against all 35 archive files/modes. Linux and native Apple Silicon
release builds, formatting, Clippy and selected proof-free checks passed:
**33 tests per platform, 0 failures, 2 proof tests ignored, 3 capacity/history
tests skipped** (`--skip capacity --skip crosses_old_limit`). An initial Linux
invocation inadvertently started capacity cases: the coin case completed and
the note case was stopped. That invocation is not a full-suite pass; no proofs
were generated. The subsequent selected run is the result reported above.

Fresh Linux offline source capture checked all **2,027** retained node files
against the public map, chain-byte integrity and unsupported-capability refusal.
Wrong-hash and symlink backends refused; exact pinned selection succeeded with
no keys created. Both split-download profiles verified, including management
without wallet/private files. Both formulae passed native Ruby syntax checks;
new Homebrew installation/upgrade and clean-machine tests remain pending.
The source projection has a new Git/archive/capture identity and omits operational
qualification programs; no new node/container build qualifies that projection.

These checks used real controller/backend programs plus ordinary fixture tests,
not a new AWS/node/proof workload. The distributed Linux binaries are newly
path-remapped builds with their own published hashes. Mac remains source-only;
there is no Mac executable, signing/notarization or browser-download claim.
