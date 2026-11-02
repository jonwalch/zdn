# Offline deployment handoffs

The existing handoff export/import commands use the same private tar publisher,
independently conveyed SHA-256, exact regular-file inventory, bounded decoder,
create-only atomic deployment installation and local state transaction for both
deployment families. No handoff is cloud authority or permission to resend an
unknown command, renew a lease, submit a build, or run an adapter.

Ordinary archives retain `zdn-deployment-handoff/v1alpha1` and their existing
encoding. Explicit external requests and external source preparations use
`zdn-external-deployment-handoff/v1`; the versions cannot be interchanged. External
validation currently requires Linux, where the external typed contracts exist.
Neither inspection nor export/import invokes the companion, Linux helper, node,
Docker, a source checkout, or cloud tools. The pinned companion **bytes** are a
required public artifact, not an installed/executable companion requirement.

## External evidence

Only closed public artifact slots and named recovery files are portable:

- Canonical external request, package, descriptor, native rules, wallet profile,
  seed blocks, compiled result, image proofs, companion and helper pins.
- Native cohort and public identity records, lifecycle evidence, provisioning and
  original runtime manifests, exact installer bytes, authenticated SSM request
  histories, producer/gateway proofs and revision-bound public endpoints.
- External source/runtime update intents, target requests, the three image
  proofs, exact SSM histories, predecessor chains and confirmed active revisions.
- Original new-volume creation intent, per-node receipt and exact checkpoint;
  the imported authorization must equal the existing proof algorithm's result.

Unknown files, foreign identities, changed artifacts, unsafe renders, missing
proofs, links, special files and arbitrary nested directories fail closed.
Credentials, generated Pulumi projects, diagnostics and generated `health/`
observations are never traversed. Excluded workspaces must be real directories,
not links; health observations have no archive slots or recovery authority.
Host cookies, private keys, node databases and wallet data have no archive slots.

Completed `external-up` operations are distinct from ordinary `devnet-up`.
Staged updates and identified unresolved `external-update` operations can retain
their durable pending selection and the final unfinished SSM attempt. Earlier
attempts, immutable requests and confirmed revision results still validate.
Every retained successful external-update receipt, not only the latest one,
must bind admitted canonical source/image intent inputs using the controller's
`operation_inputs` and its successful update UUID/node result. Removing a whole
revision, clearing active image pins and repinning the archive cannot roll back
that retained history. Successful update phases stay binding when readiness is
unfinished; predecessor and confirmed-frontier checks remain independent.
Import does not clear `unresolved_operation`, `pending_update`, unknown build
submission state, cancellation information or other recovery barriers. Initial
unfinished `external-up` is not supported: reconcile it on its original controller.

## Initial external source builds

`Deployment.external_source` uses the controller's
`foundation::external::source::SourcePreparation` API, schema
`zdn-external-source-preparation/v1`, record `external-source-preparation.json`
and root `external-source/`. Handoff retains only its eight public slots, exact
source archive/receipt, published preparation record, native build attempt and
pinned exporter. Successful output proofs are retained and validated when present.
The same source evidence remains attached after the request is materialized.

The atomically published `external-source/external-source-preparation.json` can
recover the narrow crash window before the outer record/deployment save. Export
validates its deployment scope/owner binding and carries that explicit preparation
in the archive without repairing or modifying the sender. Unknown build outcomes
remain unknown after import; removal still refuses an uncertain billed job.

The handoff adaptation of new-volume verification is read-only and follows
`foundation_live/new_volume.rs` (including original timestamp window, exact
resource/attachment/tag identities and serialized proof hashes). Changes to that
wire algorithm must update both readers; it does not maintain another journal.

## Offline regression coverage

`tests/handoff.rs` extends `tests/handoff_export.rs` and
`tests/handoff_import.rs` with inert synthetic external packages, staged request
relocation, completed external-up evidence, pending updates, external initial
source preparation, unknown source submissions, atomic-publication recovery,
foreign request/SSM negatives, changed archives, closed slots and excluded private
workspaces. Completed two-revision export/import/re-export, historical receipt
input/result mutations, repinned whole-update omission and health directory/link
exclusion are covered by additional synthetic cases. No test in this file executes
its synthetic companion/helper or starts a real build. Compilation/test execution
belongs to the coordinating validation run; fixture results do not qualify live
deployment or recovery behavior.
