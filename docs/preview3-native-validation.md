# Preview 3 bounded native validation — 2026-10-28

**Selected source-installed Apple Silicon journey: PASS.** This is not full beta,
general Mac support or browser-download qualification. No published executable,
source archive, notice or checksum asset was replaced by this validation.

## Candidate and scope

The controller was installed from the exact Preview 3 source archive using
`cargo +1.97.1 install --locked`. All 297 source-file bytes and executable modes
matched the public source tree. The existing source-built wallet installation
was reused; no release binary was silently substituted or rebuilt.

| Component | Identity |
| --- | --- |
| Controller source | `fe2ccf325b57f8538973c31bcf26322a416eae55`, tree `4ac7f539efa6bf8154073097bb3aa18b129022f5` |
| Source archive SHA256 | `5e7c167e690d42b1f16d46716cf6351e7a8d3a9cdbce59b3746ac5c98c272737` |
| Installed native controller SHA256 | `a6018f1fe16cb203a48a33ee8cd5534c7c691c4fcf203556b0b1308a9e3a6601` |
| Linux host/helper SHA256 | `335ce83c461a087bb359b2d98f509815061595e9dfdfe57ef2325ff014d0085a` |
| Wallet source | `70ccc7f45ef9ecdea46151719b82b356b48e2d76`, Common 3.0 |
| Installed source-built wallet SHA256 | `18d74c0758b503f67126d99656c4f058b83ceb528a442f463b1bb8e49eb7472d` |
| Node revision | `8ca2da93655148d39fbb88267f9902743eba6f62` |
| Node source capture SHA256 | `b558c0129145d025c94457f0b5b93a554640e5f2872fba507949fc8b43f646c2` |

Qualification reference: canonical beta plan v1.0 / 2026-10-23, research revision
`4983af5370f28087c84245dba52e150f65776d54`. Selected REL-02 source-installation,
REL-03 private-journey, PAY-01 payment and CLN-01 cleanup subcases were exercised;
this does not close those entire case families.

One authenticated non-root AWS source profile performed setup and cleanup in a
dedicated development account. The frozen run permitted one actual source build,
one private node, normal 25-second blocks and 100-block reward maturity, and
exactly three original payments. There was no automatic whole-run retry,
replacement build/payment, accelerated mining or broader operational matrix.

## Observed results

The single build completed `SUCCEEDED`; exactly one node became ready and healthy.
All three original transactions confirmed on the selected node's canonical chain:

| Payment | Amount (zat) | Fee (zat) | Input (zat) | Change (zat) | Inclusion height |
| --- | ---: | ---: | ---: | ---: | ---: |
| Funding → Alice | 100,000,000 | 15,000 | 625,000,000 | 524,985,000 | 101 |
| Alice → Bob | 10,000,000 | 10,000 | 100,000,000 | 89,990,000 | 104 |
| Bob → Alice | 4,000,000 | 10,000 | 10,000,000 | 5,990,000 | 108 |

Amounts, fees, input/change accounting and inclusion were checked against saved
receipts and fresh node observations. Each had at least one confirmation at
observation. Final confirmed-unspent and spendable balances were **Alice
93,990,000 zat / Bob 5,990,000 zat**, without pending spends or reservations.
Reopening the original send UUID preserved its transaction/evidence. A coherent
38-file wallet backup matched hashes and allowed reading that original transaction.

Ten incomplete-sync outcomes recovered within the existing bounded read-only
loop; all 47 classified reads exited successfully. Exact classified-refusal
allowlist retry branches were not hit by this live run. Separately rerun offline
validation covered those branches, exhaustion and immediate rejection of backend,
canonicality and compound cleanup errors: 18 candidate cases and two original
controls, with no AWS/network/payment subprocesses.

The node disk was independently observed retained and available before subsequent
delete-data cleanup. Product lifecycle commands completed; keep-backend and final
independent audits passed **200 / 199 observations**, respectively. The complete
protected account baseline matched recursively, including previously retired
test keys. The recorded instance was terminated and owned infrastructure met
the audit's terminal/absent conditions. The run-owned key is `PendingDeletion`,
scheduled for **2026-11-27T16:49:59.233000+00:00**, not physically deleted.
The supervised run exited **0**, with joined writers and no cleanup failures.

## Evidence integrity and limits

Independent closeout verified every size/hash in a sealed 3,529-file manifest,
receipt continuity, payment economics and complete baseline equality. Operational
evidence and wallet secrets remain private; this public summary contains neither
credentials nor wallet/backup data. Key report hashes:

- Exit/cleanup summary: `8ee632ce4865a0aeab0853e196afdc64281dc0be1fe035d0bd8e02a123565a89`.
- Payment/reopen/backup result: `8ef346f816b36a6578581f8173c7f99b04f8c238a937bd4ceacd7feeec73aa95`.
- Final audit: `539f64e79f5dabadf0bc76ca78e804c73ab547fd84da22bbba85c4f48fac21a3`.

Earlier failed attempts and their audited cleanup remain recorded, not relabeled
as passes. The successful harness used isolated HOME/data state, explicit saved
profile/state selection, the actual per-node volume output and bounded exact
readiness refusals. Product guards, component pins and payment semantics were
unchanged. The earlier refusal's internal timing was not directly recorded.

This is one trusted validating private node, not independent consensus. Confirmed
UUID reopening/coherent backup does not establish lost-dispatch, hostile rollback
or reorg recovery. Nor does this run establish physical KMS deletion, billing
closure, all-service global cleanup, formal platform support, clean-machine,
quarantine/signing/notarization or legal clearance. Ordinary CI outcomes remain
separate from live qualification; see [testing](testing.md).
