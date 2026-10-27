# Selected-node image updates

`devnet update` replaces explicitly selected nodes' pinned images on their
existing hosts and chain disks. It does not run Pulumi, allocate resources,
format disks, change consensus/configuration, replay bootstrap, or update the
installed Rust helper. The original cluster request and installation identity
remain immutable; confirmed image revisions are recorded separately per node.

Only native-runtime deployments and native update intents can execute. Historical
Python deployments/updates are inspection and cleanup data, not resumable work.
Recreate disposable test networks with fresh bindings; no in-place conversion or
legacy dispatcher repair is supported.

Before updating, check storage-format and peer compatibility for the exact old
and new images. A successful build alone does not establish either.

## Choose inputs and exact nodes

After reviewing forward storage and mixed-version peer
compatibility for the exact old and new images:

```sh
zdn devnet update NETWORK-ID --node node-2 --node node-3 \
  --image-record candidate/image.json \
  --image-manifest candidate/image-manifest.json \
  --image-config candidate/image-config.json \
  --acknowledge-storage-compatibility --yes
```

Alternatively, copy the original configuration to a separate file and change
only `node.source` and `node.build`:

```sh
zdn devnet update NETWORK-ID --node node-2 --source-config candidate.yaml \
  --build-helper /path/to/linux-amd64/zdn \
  --acknowledge-storage-compatibility --yes
```

New source updates require a Linux helper implementing
`zdn-build-export/v1alpha2`. `--build-helper` is a private build input, not a
replacement for the installed host helper. Its exact bytes are saved with the
original build attempt before publishing the update intent. CodeBuild checks
the pinned object's owner, version, size, digest and protocol before source
extraction or Docker. There is no Python fallback. Resume takes no new helper
input. Only the current exporter protocol is supported; old build attempts are
not migrated or kept executable in this unreleased beta.

Use the deployment's saved `--profile` and `--state-dir` when not using defaults.
The current CLI uses the same verified managed-tool installation as `up`, but
never executes Pulumi on the update path. There is no implicit all-node target.
Duplicate/unknown nodes, changed topology, runtime configuration, chain, rewards,
helper, access or service settings are rejected. The acknowledgement is saved
against the selected old revisions and candidate; it is not automated evidence
of compatibility or authorization to downgrade after database writes.

Updating a node that hosts lightwalletd is currently rejected before billed
work: its existing service contract pins the original node image. Other nodes
may be updated while lightwalletd remains unchanged. Legacy deployments without
the durable bootstrap-completion contract are unsupported.

## Transaction and recovery

An update UUID is printed to stderr and saved before cloud/build work. Source is
captured once; build receipts and image artifacts live under `updates/UUID/`.
The recovery inputs are committed before the pending intent is published. An
interrupted local preparation may leave an unused UUID directory, but does not
block the deployment. The intent binds the complete image or source contract
in the same deployment write.
Source updates reuse exact-image reuse, cache and uncertain-build recovery.
Keep the original configuration, deployment receipt, archived installers and
the entire update directory. Resume never recaptures the working checkout.
Once a candidate revision has been saved, resume uses its embedded build contract,
even while some selected nodes remain unfinished. A missing local
`build-contract.json` sidecar does not trigger rebuilding; any present sidecar
must agree exactly. Before a candidate exists, source-build recovery still needs
the saved contract and original build inputs. Resuming a candidate still checks
its staged artifacts and ECR digest under the normal lease/reconciliation gates.
Native update intents require their original native attempt before any build;
missing receipts cannot silently start a legacy job. Once the candidate exists,
native handoffs retain the settled attempt, result and three verified build
outputs for exact product-managed cleanup. They omit the now-unused exporter
executable and source workspace. Pre-candidate update handoff remains unsupported.
Controller handoff supports only the narrow interrupted-update case with complete
candidate/history and exact scripts/journals for every target. The last attempt
of an unconfirmed target may remain in flight or uncertain; the receiver recovers
the same command before proceeding. Confirmed and historical attempts must be
terminal and certain. Targets without saved command evidence still require
source-controller recovery. Staging prepares exact scripts and original Prepared
journals for all selected targets before any mutation dispatch, so an interruption
after staging preserves untouched targets for handoff as well. Repeating staging
does not retry failed attempts or replace uncertain work. An interruption during
partial preparation can still block transfer; missing journals are never inferred.
See
[controller handoff](private-devnet.md#controller-handoff).

Root `--format json|jsonl` also supports updates, including source builds and
resume. JSON has one terminal record; JSONL exposes the saved `update-prepared`
UUID, operation creation and durable `update` phase transitions. The optional
private `--progress-file NEW_PATH` mirrors those events without changing JSON
stdout. Terminal results retain `data.updateId`, known network/operation IDs and
sanitized receipt/build observations, never raw provider diagnostics. A prepared
UUID is not proof of remote work; missing/partial events never authorize retry.
The existing acknowledgement, consent, explicit-node and reconciliation gates
remain required. See the [machine contract](automation.md#implemented-lifecycle-execution-events).
`update-observed` reports each fresh node confirmation after its revision and
completion are saved atomically, then the saved finished state after cluster and
service checks. Its sanitized snapshot is retained under terminal `data.update`.
A reporting failure preserves completed assignments; resume reobserves those
nodes instead of replacing their images again. Finished state is not command
success until later lease cleanup and reporting succeed. `ssm-observed` also
reports sanitized saved host-command attempts; terminal `data.ssm` retains the
latest one, not an aggregate success result or permission to redispatch.

The driver takes the deployment lease, checks exact saved instance/disk
ownership and attachments, and verifies candidate bytes/config/ECR digest before
remote replacement. Selected followers are updated sequentially before the
producer. Non-selected nodes retain their revisions.

On each native host, the separate image-update request binds the original
immutable runtime manifest. Volume ownership, configuration, helper, producer
authorization and producer journals retain their original identity.
The forward-only revision journal is durable before activation, so interruption
does not turn a retry into an original-image replay.
The target is downloaded, verified and pulled before services stop. A durable
maintenance hold prevents premature producer restart during interruption or
reboot. Starting the node can also auto-start its systemd Wanted producer before
the retained journal reflects the new PID/lock. While the hold is active, the
updater explicitly stops that producer and verifies it is stopped before strict
readiness. Only then is the hold cleared and bounded native producer activation
used; identity, PID, lock and interval checks remain strict.
Completed retries without a hold do not stop a healthy producer. Restart uses
the existing disk and requires fresh readiness, without seed submission.
Previously authorized production may resume after local readiness;
the controller requires fresh cluster and enabled-service observations before
marking the update finished.

Native execution never replaces or repairs a Python dispatcher. The old
`--migrate-update-dispatcher` compatibility flag and historical Python renderers
are removed. Data-only recovery receipts remain available for inspection/cleanup;
they cannot authorize native work. Original native scripts,
exact command journals and completed revision history remain required for
recovery, handoff and fresh health checks. Missing, changed or unfinished evidence
fails closed.

When the client-gateway host is updated, observation authenticates its unchanged
installed native gateway and original runtime manifest, then checks the exact confirmed
node image/revision. Gateway service and volume identity remain unchanged; the
original-image assumption is not reused as a post-update readiness gate.

```sh
zdn devnet update NETWORK-ID --resume UPDATE-UUID --reconcile \
  --acknowledge-storage-compatibility --yes
```

Unknown SSM submissions reconcile the exact saved command; they never authorize
blind redispatch. Cached command success cannot replace a fresh observation.
Confirmed nodes and partial completion are saved atomically. Status exposes
saved revisions/progress but remains inventory-only (`liveReadinessChecked:false`).
Pending updates block new updates, `up`, destroy, and local endpoint export/connect.
An expired lease requires the exact ETag shown by status and
`--recover-lease-etag ETAG` on the resume command. Lease expiry alone does not
prove an earlier command stopped.

There is no automatic rollback or receipt-deletion retry. After the target may
have executed, its database writes may make the old binary unsafe. Terminal
build failures and missing/corrupt preparation receipts fail closed and require
inspection; do not bypass them by deleting saved state. A settled mixed-image
deployment remains observable and destroyable. Unchanged `up` preserves confirmed
revisions rather than rerunning original node installers. It still reconciles
producer and enabled client services in the mutating install phase, then requires
fresh readiness. A cached activation receipt may describe an earlier image;
recovery settles that command before checking the active image and, if needed,
requesting one bounded producer restart. It does not rewrite historical results.

Before publishing finished state, the controller durably saves the completed
intent at `updates/UUID/completed.json`. Preserve this history along with the
revision artifacts and command journals: [controller handoff](private-devnet.md#controller-handoff)
uses it to validate complete per-node revision chains, including repeated updates.
Handoff supports settled mixed-image deployments and the narrow interrupted case
described above. Missing historical evidence and uncertain confirmed/historical
commands remain blockers. Conflicting completion metadata is never overwritten
by a retry. If completion metadata was saved before a crash publishing finished
deployment state, handoff retains both states only when every target is confirmed
and the metadata matches exactly. Resume still runs fresh checks before finishing;
import alone never upgrades the pending intent to success.
