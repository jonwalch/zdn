# Local identities and receipts

The local state store creates no AWS resources,
reserves no cloud ID, and does not claim that a network is running. Every binding
has `reservation: unreserved`.
Foundation commands also maintain a separate [S3 reservation and operation lease](aws-state.md#reservations-and-deployment-leases).
The local binding field alone never proves cloud ownership. See the
[foundation lifecycle](foundation-lifecycle.md) for executed AWS phases and recovery.

## Network identity

`StateStore` keeps local bindings in a dedicated directory outside both the
configuration's parent directory and the source worktree. It checks these
boundaries separately, including when configuration and source are in different
checkouts. `BindingContext::new` resolves the configuration and worktree paths.
Its fingerprint includes the configuration path, worktree, branch, team ID, AWS
account, and region. The label is separate from this fingerprint.
For local source, the CLI uses the source checkout's Git context. For a release
or image, it uses the config checkout's context. A config outside Git omits both
worktree and branch. Git lookup errors do not create an unscoped binding.

After setup, `zdn identity bind` derives team/account/region from the saved local
profile selected by the configuration. An explicit offline scope still works
without that profile: supply `--team-id`, `--account-id` and `--region` together.
Partial scopes and contradictions with an existing saved profile refuse.
For predeployment wallet creation, `zdn identity bind --manifest FILE` registers
reviewed manifest bytes once for that network UUID. Later replacement bytes or
disagreement with deployed consensus refuse; this is not cloud readiness or
permission. See [wallet onboarding](wallet.md#create-the-reward-wallet-before-deployment).

- `bind` explicitly creates a UUIDv4 identity or updates the existing label.
  Changing a label keeps the network ID and resource names.
- `binding` requires an existing binding for the complete context. It does not
  adopt a network because its label matches.
- `resolve` accepts a full ID, a unique prefix, or a unique label within the
  selected team, account, and region. A matching label in the current context
  selects its saved binding. Ambiguous selections report the full candidate IDs.
- `attach` explicitly imports a binding receipt. It requires the expected full
  UUID and matching team, account, and region. It cannot replace a different
  existing binding. Importing a receipt grants no IAM permission and proves no
  cloud ownership.
- Resource names include the complete UUID. An excessive name is rejected,
  rather than shortened into a possible collision.

The store creates new state directories with mode `0700` on macOS and Linux.
Metadata files have mode `0600`. It does not change permissions on existing
directories. An existing state root must exclude access by group and other users;
otherwise opening it fails before creating metadata. Use a dedicated private
directory for `--state-dir`. If permissions change on an existing state root,
inspect and repair that directory explicitly before reopening it.
The store rejects a symlink used as its root, lock file, or state file. It resolves
the root's parent path when opening the store. Use a private parent directory;
the store does not protect against another process running as the same user.

## Durable writes

`store.lock` serializes readers and writers across processes. Lock acquisition
waits at most two seconds by default, then reports that the store is busy. All bindings and
operation receipts are in one versioned `state.json` file. A write uses a private
temporary file, flushes it with `sync_all`, replaces the state file atomically,
and flushes the directory. The previous state remains intact if validation or
serialization fails before replacement. A process crash cannot expose a partial
JSON write. An error after replacement can have an uncertain outcome; reload
the receipt before retrying.

Malformed state, unknown fields, unsupported versions, and invalid fingerprints
fail with an error. The store does not silently reset them. Preserve damaged
state before recovery. The format is currently version 1; no migration from a
previous released format is needed. The current file limit is 16 MiB.

## Operation decisions

An operation records its network ID, scope, kind, ordered phases, and original
configuration hash. A local-source operation also records the manifest and
archive hashes. These hashes are immutable. `resume` rejects changed inputs.
The caller must restore and verify the saved archive before using it; a hash
record alone does not prove that an archive still exists or matches its bytes.
The CLI verifies the saved receipt and archive without opening the original
source checkout during resume. New operations still validate the live source
directory and requested revision before recording those hashes.

Persist `Running` before starting an effect. Then save its result. Each update
requires the receipt revision the caller read, so stale writers cannot replace
newer results. Earlier phases must succeed before a later phase can start.
An earlier phase can retry only while all later phases are still pending.
Reconciliation cannot grant a safe retry after a later phase has started or
finished. It can still record a checked success or uncertainty. Reconcile any
later effects, then use a new operation if a prerequisite must run again.

| Saved state | Resume decision | Reason |
| --- | --- | --- |
| Pending | Run | No effect was started. |
| Failed, with an explicitly safe retry | Retry | The adapter established that retry is safe. |
| Running or unknown | Reconcile outcome | The effect may have happened before the process stopped. |
| Failed, with no safe retry established | Reconcile outcome | Failure does not prove that nothing happened. |
| Succeeded | Reconcile success | Recheck the actual result before skipping the phase. |
| Cancelled | Stop | The phase has an explicit terminal cancellation result. |

Decisions are ordered. They are not executable cloud actions. An adapter must
reconcile each earlier phase before acting on a later one. `reconcile_phase`
saves an independently checked result; the state store cannot check AWS or node
state itself. The separate [foundation lifecycle](foundation-lifecycle.md)
supplies the cloud executor.

Cancellation records intent. It prevents a new phase or safe retry from starting.
It does not mark an active job as stopped. Running or uncertain work still needs
reconciliation. Save cancellation as a phase result only after checking it.

Receipts hold metadata and safe phase results. Callers must not put credentials,
wallet keys, signed secret material, or unredacted service errors in them. These
records do not contain a cloud lease, an S3 reservation, or a Pulumi lock.

## Fast checks

Run these local tests from the repository root:

```sh
cargo test --locked --test state_store --test operation_receipts
```

The tests use temporary directories and real helper processes. They cover
concurrent creation, distinct context identity, rename stability, ambiguous
selection, explicit attachment, separate configuration and source boundaries,
private file modes, rejected metadata symlinks, stale revisions, bounded lock
contention, unchanged permissions on existing directories, malformed state
preservation, and incompatible versions. A parent
process kills a helper before and after a durable receipt update. On
restart the store reads the complete prior or new receipt, and the process lock
is released. These checks do not simulate power loss or prove filesystem
durability on every storage device.

Resume tests cover changed hashes, phase order, unknown outcomes, explicit retry
safety, and cancellation. They reject earlier retries once a later phase has
started, including receipts saved by an older version. No Docker, AWS access,
live chain, or shielded proof is used. [Cloud reservations and leases](aws-state.md#reservations-and-deployment-leases)
are separate from these local store checks.
