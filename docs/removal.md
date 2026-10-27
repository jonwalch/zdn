# Participant and team removal

These administrator commands use the original
product receipts and existing Pulumi stacks, not an AWS resource-name cleanup
script. Keep the original private state directory and all audit receipts.

## Remove a separate participant grant

Review the offline proposal first (no AWS calls or managed tools):

```sh
zdn setup remove-participant --receipt-dir "$STATE/participants/$BOOTSTRAP/$NETWORK"
```

Stop participant connections and other writers. Removal refuses **any active SSM
session on the grant's target instances**, including another participant's
session; it never guesses session ownership or terminates sessions. While the
grant still exists, obtain a disposable participant session through your normal
approved credential workflow and retain its still-valid credentials in a private
AWS profile for the later read-only denial check. Do not put credentials in CLI
arguments, logs, or receipts.

```sh
zdn setup remove-participant --receipt-dir "$STATE/participants/$BOOTSTRAP/$NETWORK" \
  --yes --revocation-profile OLD_PARTICIPANT_SESSION
```

The administrator profile comes from the original participant request. The
revocation profile must contain cached STS credentials from the **original
RoleId**, with an enforced participant session name. An administrator/developer
source profile, automatic re-assumption after deletion, an expired token, a
missing document, or a network error cannot qualify the check.

Removal validates the original protected checkpoint, live immutable IAM identity,
trust, tags and policies; unprotects only exact owned resources; destroys the
separate participant stack; independently observes IAM absence; and removes the
empty stack. It preserves `participant.json` and writes `removal.json` beside it.

Read-only backend/document preflight failures do not create a new participant
receipt. An older receipt with `stackStarted: false`, `uncertain: false` and
`complete: false` can also be closed with the same removal command. This path
requires independently observed **stack absence and typed IAM role absence**;
an existing role/stack or failed observation refuses. It never deletes or adopts
resources based on preflight intent. The preserved creation receipt and
`removal.json` with a null checkpoint record absence-only closure. The command
reports `status: not-started`, not proven revocation. `--revocation-profile` is
refused because there is no original RoleId to qualify. Started or uncertain
setup still requires the original ownership evidence and, when uncertain,
`--reconcile`.

Without `--revocation-profile`, successful destruction reports
`status: revocation-pending`. Repeating with the profile can add evidence without
recreating the grant. `revocationVerified` is narrowly scoped: **read-only
`ssm:GetDocument` authorization denial on every fixed service**, using still-valid
old credentials. It is not STS invalidation, a `StartSession` test, or proof that
already established TCP tunnels were terminated. New assumptions and real
endpoint-import connection denial require separate live qualification. The CLI
does not probe `StartSession`, which can create a real session and invoke the AWS
session-manager plugin.

If the optional old-session probe fails **after role/stack deletion**, inspect the
receipt and reconcile bookkeeping **without `--revocation-profile`**:

```sh
zdn setup remove-participant --receipt-dir "$STATE/participants/$BOOTSTRAP/$NETWORK" \
  --yes --reconcile
```

This reobserves role and stack absence and checks active sessions; it clears
removal uncertainty without recreating the grant. `revocationVerified` remains
false and the result remains `revocation-pending`. In particular,
`InvalidClientTokenId` from old-session STS is **not** `GetDocument` AccessDenied
evidence, even if a recorded credential expiry is still in the future and
administrator STS succeeds. Do not relabel that failure as proven revocation.
Then destroy the network through the current network CLI and proceed with the
resource-closure team teardown below.

## Remove an originally created team

An imported team/profile is not authority to delete a backend. Team removal
requires the matching original `profiles/NAME.bootstrap.json`, and the completed
original `NAME.access/access.json` when access setup exists. Use the original
administrator AWS profile, not the deployment role being removed.

Before removal:

- Destroy every network through the normal product lifecycle, explicitly deleting
  retained data. Cleanup receipts and independent live inventories must be empty.
- Remove each separate participant grant and reconcile any removal uncertainty.
  Scoped live denial is optional evidence, not a prerequisite for team teardown
  once the exact granted resources are closed.
- Reconcile uncertain build submissions through the build lifecycle. Every known
  cloud build must be terminal and receipted. Unknown builds/images/objects refuse.
- Stop all controllers, submitters and data writers. The local locks are not a
  distributed maintenance lock; `--writers-stopped` is an operator attestation.

If source launch stopped after saving source-input receipts but before a verified
node request, use the same `zdn devnet destroy NETWORK --yes --delete-data` path.
It retains ordinary ownership/lease/inventory checks; it does not cancel or
reconcile a cloud build. Known builds must still be terminal before team removal.
An actual health-test foundation continues to use `zdn foundation destroy`.

```sh
# Offline, read-only proposal. --plan is an explicit alias for this default.
zdn setup remove-team --state-dir "$STATE" --profile CREATOR --aws-profile ADMIN

# Complete teardown after the network/data and participant steps above.
zdn setup remove-team --state-dir "$STATE" --profile CREATOR --aws-profile ADMIN \
  --yes --delete-data --writers-stopped
```

For a deliberate intermediate boundary only, `--keep-backend` retains team state
while removing owned administrator/build resources. It is not a required step
before complete removal. Omit default `--profile` / `--state-dir` flags when using
the default local profile and state location; keep the original administrator
`--aws-profile` explicit.

The plan is a local proposal (`liveOwnershipChecked: false`), not an AWS preview.
Execution rechecks ownership before effects. Active networks/builds and unknown
resources fail before cloud or Pulumi mutations. Externally managed deployment
roles/boundaries are never adopted or deleted. Shared/unrelated namespaces,
foreign IAM consumers, changed receipts/checkpoints/resource incarnations,
current Pulumi locks, replication/Object Lock and unexplained data are refusals,
not authority to broaden cleanup or repair settings.

The AWS CLI overlaps the 12 independent bootstrap-wide EC2 inventory requests,
with at most four subprocesses at once. All started workers are joined before
returning, including on error; failed, malformed or incomplete inventory still
blocks mutations. Network artifact cleanup uses bounded 50-version pages with
projected key/version identities. Ownership checks, team version-deletion phases
and backend-last removal remain unchanged. See
[deployment performance](deployment-performance.md) for scope and validation.

For each original participant receipt, execution validates the request and saved
checkpoint, requires matching completed, non-uncertain stack removal and IAM role
absence, and freshly queries each deduplicated **exact instance ID individually**
(not tag filters). Each must return typed `InvalidInstanceID.NotFound` or a
complete, exact matching terminated record. Every exact granted service document
must return typed `InvalidDocument`, and active sessions on every exact target
must be absent. This also covers untagged/orphan participant resources missing
from network outputs. Live, stopped, shutting-down, malformed, mismatched,
truncated or failed observations refuse before mutations, including on retries.
`participantClosureScope` records this separate resource-closure scope; it does
not claim STS invalidation, `StartSession` denial or `GetDocument` denial, and
does not change participant revocation evidence. Equality-bound team evidence
contains no observation timestamps or terminated-versus-absent variants.
Comparison also excludes the network's last-operation ID and the participant's
optional `revocationVerified` bookkeeping, so another destroy attempt or a later
denial probe does not strand cleanup. Original saved evidence is not overwritten;
ownership, cleanup verdicts, checkpoints and fresh live checks remain mandatory.
Unstarted grants require the absence-only closure receipt described above, then
the same fresh role/target/document/session checks. Directories left by project
preparation or failed preflight with no creation or removal receipt confer no
ownership and do not block teardown; independent team-wide live inventory checks
still apply.

The managed flow purges exact receipted build-source/result/pointer keys, known
image digests and the dedicated build cache; then destroys the protected
administrator/build stack and observes resource absence. Backend deletion is
last. It permits only known stacks/history and exact network metadata. Current
stack JSON **and `.json.bak`** require an inspected immutable version with the
exact stack identity and no resources or pending operations. Historical lock
versions are allowed only under exact owned stacks when their current version
is a delete marker. No arbitrary state-object or prefix purge is permitted.

S3 version inventory uses explicit key/version continuation markers, with at
most 100 pages and 10,000 combined object versions/delete markers per bucket.
Every page is collected and checked before ownership preflight can authorize
deletion. Missing/repeated markers, duplicate versions, incoherent latest flags
and bounds overflow refuse cleanup without broadening its ownership scope.

KMS is **scheduled for deletion in 30 days**, not reported deleted. Final output
contains `status: kms-deletion-pending`, `kmsState: PendingDeletion`,
`kmsDeleted: false`, and the observed `kmsDeletionDate`. Private profile,
creation, network and removal receipts remain for audit. There is no automatic
local profile erasure or KMS waiting-period bypass.

## Interrupted removal and bounds

After an uncertain result, inspect the journals and rerun the **same command**
with `--reconcile` (and the same destructive consent). Reconciliation reobserves
saved immutable identities and accepts only owned deletions/protection changes;
it never refreshes/adopts replacements. A missing stack without saved removal
intent is not success. Repeated completed removal observes absence again and
does not reschedule an already pending KMS key. Re-running setup after removal
intent is blocked, rather than silently recreating access/backend resources.

For an interrupted source build with a saved job ID, `remove-team --reconcile`
can observe that exact job's terminal outcome without resuming network setup.
It checks the saved account/project/source buildspec and requires a known
terminal status with an end time. A successful job missing local output is
verified through the existing bounded S3 result/manifest/config reads and
independent ECR digest comparison before its image becomes deletion authority.
This path never submits/stops builds, publishes reuse records, or provisions
hosts. Active jobs, unknown submissions and mismatched output still refuse.

Journals are `NAME.bootstrap.removal.json`, `NAME.access/removal.json`, and
each participant's `removal.json`. Keep them unchanged together with the
original receipts. `--managed-dir` selects an existing verified tool install.

Automatic inspection is deliberately bounded: at most 10,000 combined S3 object
versions/delete markers per bucket inventory, 100 CodeBuild jobs, and 64 KiB per inspected backend JSON
object. AWS subprocess responses are captured only in memory, up to 1 MiB per
stream; larger responses refuse even below an inventory's item-count limit.
Tool-version probes retain their separate 16 KiB limit. Incomplete/truncated
inventories refuse, not partially succeed. Initial
build receipts under each network's `build/` are recognized; unrecorded or
additional update-build history is not inferred. Resolve such cases through
reviewed product support rather than removing journals or weakening guards.

After removal, independently inspect AWS for remaining resources and check that
removed participants can no longer connect. A successful command is not proof
that every AWS policy has taken effect or that all billing has ended.
