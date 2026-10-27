# Private node deployment

`zdn devnet` implements private nodes, the block controller, and private client
services. It creates one to three private EC2 hosts, gives each host its own
retained chain disk, and starts a pinned Zakura container. It loads saved history
and checks actual node rules, history, and producer templates through
authenticated loopback RPC.

Fresh CLI requests always select native Rust node/gateway/lightwallet execution;
`--native-runtime` is now an optional compatibility flag. Old Python requests
remain inspectable and removable but cannot execute health/up/update or be
converted. Recreate test deployments with new bindings.

New requests start the [block controller](block-producer.md) after every node
passes fresh readiness. The default interval is 25 seconds.
Initial node installations and lifecycle readiness observations run concurrently
across distinct hosts, with up to four outstanding remote commands. The scheduler
uses the selected node collection, not fixed three-node slots; the supported
topology remains one to three nodes. Each host retains its own recovery journal,
and producer activation still waits for all nodes. See
[deployment performance](deployment-performance.md) for failure/cancellation
semantics. The separate diagnostic
`health` command retains its per-component observation/reporting flow.
Lightwalletd has [automatic private deployment](lightwallet.md).
New `init` output defaults to `--service-preset node-only`, with
all optional services disabled. Use `--service-preset lightwallet` to enable only
lightwalletd and supply its three pinned image inputs on first render. Existing
configs are unchanged: supported deployments require `services.wallet: false`
and `services.faucet: false`; also set `services.lightwallet: false` for nodes only.
Missing or partial service inputs are rejected before staging.
An older request may have saved enabled flags while deploying nodes only.
Its immutable configuration is not migrated: `render/up`, including `--reconcile`,
now reject that request. Preserve its receipts and use `status` or
`destroy --reconcile` by deployment selector; those commands use saved state and
do not require the current config. Editing the service flags is not an in-place
migration. Use a new binding for a new explicit node-only launch.
Every result keeps
`launchReady: false` and payment qualification
pending. `devnet status` reports AWS inventory and saved outputs; it does not
perform a fresh node readiness check.

## Fresh health checks

```sh
zdn devnet health my-feature
zdn devnet health my-feature --wait --timeout-seconds 120
```

`health` issues new read-only SSM observations for every node, the scheduled
producer, and enabled lightwalletd/client gateway services. Its versioned JSON
report includes per-component status, freshness and observation timestamps.
It exits successfully only when all required components are ready. Unavailable,
invalid or unchecked observations never count as ready. Payment qualification
remains pending and `launchReady` remains false.

Without `--wait`, it performs one observation pass. With `--wait`, it retries
recognized transient AWS failures and validated not-ready producer/service
reports until ready, cancelled or timed out. Authorization failures, malformed
results, identity mismatches and terminal remote command failures stop without
retry. A failed node observer cannot distinguish startup delay from an invalid
installation, so health reports a sanitized failure rather than guessing that
another attempt is safe. After local proof validation and credential verification, all
observations and retries share one monotonic deadline (default 120 seconds,
range 1–7200). Remote read-only commands can continue after local cancellation
or timeout; health never starts, restarts or repairs services.

This command needs no Pulumi installation or mutation lease. It rejects
destroyed, unprovisioned, foundation-only or unresolved deployments before
credential setup. Fresh diagnostic journals live under `diagnostics/health/`,
are never reused as recovery evidence, and are excluded from controller
handoffs. Health does not reconcile an interrupted operation: resume that
operation explicitly first. After successful recovery, abandoned historical
read-only observation journals are preserved but do not block new health checks;
authoritative installation, volume and complete update-history proofs still apply.

## Prepare

Install the [AWS prerequisites](../README.md#requirements-and-build) and complete
administrator role setup. Existing teams must repeat `setup bootstrap` with the
same settings and an administrator profile to add the runtime artifact policy,
artifact-version cleanup permission, and scoped client-session permissions to
the deployment role.
The tool checks the installed boundary and data policy before allocation.
Externally managed access requires the administrator to supply the equivalent
policies. The health-test `foundation` commands remain available separately.

Supply these immutable inputs:

- An image in `ACCOUNT.dkr.ecr.REGION.amazonaws.com/zdn/TEAM/REPOSITORY`, pinned
  by its Linux/amd64 child manifest digest. It must provide the
  [image contract](image-contract.md), including the diagnostic RPCs.
- The image record, exact registry manifest bytes, and configuration blob. Do not
  reformat the two registry blobs. `zdn image verify --record image.json
  --manifest image-manifest.json --config image-config.json` checks them offline.
- A [consensus manifest](chain-manifest.md) and verified saved-block bundle. The
  supported loader requires a checkpoint at every saved height and no later
  checkpoint. The configured upgrades and proof-of-work mode must match it.
- A Linux x86-64 `zdn` executable built from this implementation and runnable on
  Amazon Linux 2023. The local macOS executable cannot serve as the host helper.
- A supported transparent Testnet producer reward address. This sets the
  producer's template address; it does not fund an Ironwood wallet.

No release image or host-helper download is shipped yet. A new deployment
needs its own pinned inputs. This command accepts existing images;
for `node.source.path`, [source delivery](builds.md) captures source,
reuses an exact verified image or runs/resumes a native CodeBuild job with persistent
intermediate layer caches, and verifies the image
before entering node provisioning. Its offline build preview is `devnet render`;
`zdn up` and `zdn devnet up` share the build/deploy path.

## Deploy

Create a new config with the existing image, then freeze and inspect its inputs:

```sh
zdn init --name my-feature --nodes 1 --image ACCOUNT.dkr.ecr.REGION.amazonaws.com/zdn/TEAM/zakura@sha256:DIGEST
zdn devnet render --ami-id ami-REPLACE --availability-zone us-east-1a \
  --manifest manifest.json --bundle chain.tar \
  --image-record image.json --image-manifest image-manifest.json \
  --image-config image-config.json --host-helper ./zdn-linux-x86_64 \
  --reward-address YOUR-TESTNET-REWARD-ADDRESS
zdn up --yes
zdn devnet status my-feature
```

`--nodes 1` selects one private node; omit it to retain the three-node default
(`--nodes 2` and `--nodes 3` are also supported). Saved labels such as `my-feature`
are explicit network selectors, as are full IDs or unique prefixes. No command
silently selects the only saved network. `up` is the alias for `devnet up`.

Select an Amazon Linux 2023 x86-64 AMI in the team's region. `render` saves local
copies, prints the Pulumi program, and makes no AWS calls. The later `up` uses
those saved inputs. It verifies the ECR manifest and runtime policies, holds the
existing deployment lease, publishes immutable S3 artifacts, applies the saved
Pulumi plan, and installs nodes through SSM. A reported node-ready result requires
fresh observations after installation, including the actual Docker resource
limits and the reserved host budget. Activation then starts the controller on
node 1. A final fresh observation requires a live, healthy controller. This
service continues after the CLI exits; it does not require an open connection.

Node 1 has the producer role. The internal miner is off. All hosts share a
private subnet and outbound NAT; only the selected private peer addresses can
reach P2P. Node RPC listens on authenticated localhost. See
[private topology](private-topology.md) and [host lifecycle](host-lifecycle.md).

New requests also install the client RPC proxy on node 1 and create fixed-port
SSM session documents. Installation checks the saved host identity, exact service
files, and authenticated node readiness before saving endpoint details. It uses
its own durable SSM journal and leaves the node runtime unchanged.

First formatting requires either a pinned `newVolume` authorization or the
legacy full-disk zero scan. Authorization requires a creation intent recorded
before apply, the exact new managed Pulumi volume, and matching AWS identity,
creation time, size, encryption, attachment, and absence of a source snapshot.
Tags alone do not authorize formatting. The authorized path also rejects
signatures, previous guest writes, prior claims, and uncertain format attempts.
Without authorization, the zero scan can take several minutes. See
[host lifecycle](host-lifecycle.md#install-and-restart) for recovery limits.

Installation first waits for a protected marker from successful
package and Docker setup, because SSM can be online before user data finishes.
The installer and SSM operation have bounded deadlines. Failure retains
progress and data for inspection. Later unchanged installs reuse existing data.

A peer can finish checkpoint verification before its block becomes visible in
state. If `submitblock` returns the literal `rejected`, bootstrap makes bounded
observation-only checks for the exact block and parent; it does not submit that
block again in the same loading run. Concurrent height/tip reads also require a
fresh matching prefix.
See [bootstrap reconciliation](bootstrap-readiness.md#supported-loading-recipe).

## Connect a local application

```sh
zdn connect my-feature
```

Use the printed localhost endpoints and keep the command running. Node RPC goes
through a restricted proxy on the host. The proxy permits chain queries and
`sendrawtransaction`; it refuses mining, administration, and wallet-management
methods. The node cookie stays on the host. When lightwalletd is enabled, the
command also opens its gRPC connection and checks that its observed block agrees
with node RPC. Ctrl-C closes the connections without stopping the devnet.

To share a devnet, run `zdn endpoints my-feature --output endpoints.json`.
An administrator can create the separate access role with `zdn setup participant`.
The participant runs `zdn connect --endpoints endpoints.json --aws-profile
devnet-participant` with their own AWS identity. The file has no credentials or
state-backend details. This connection path does not need deployment permissions
or Pulumi-state access. See [private connections](connections.md) for setup,
local port selection, and recovery limits.

The proxy forwards transaction submission but does not implement a wallet or
funding service. Ironwood funding, scanning, submission, and later spending
require separate [wallet qualification](compatibility.md).

## Resume

Discover saved deployments without AWS authentication, installed cloud tools or
the original checkout:

```sh
zdn devnet list --profile devnet --state-dir /path/to/local/state
```

This returns `zdn-deployment-list/v1alpha1` JSON scoped to the selected local
profile's team/account/region. Entries are deduplicated by full network ID with
sorted labels. They include receipt validity, request kind, last-operation phase
statuses, pending-update IDs and local recovery blockers. Missing or invalid
deployment receipts remain visible without exposing raw parse errors or operation
results. Snapshots can be read while another process holds the deployment writer
lock. Corruption of the shared state ledger itself still fails the command closed;
it does not salvage unvalidated identities or operation records.

`scope: "local"`, `awsChecked: false`, `liveReadinessChecked: false` and
`artifactIntegrityChecked: false` distinguish saved observations from fresh
checks. `ready-for-preflight` means no known local blocker, **not** safe-to-retry,
live ownership, lease availability, healthy nodes or qualified payments.
Foundation-only receipts remain listed but cannot use node recovery. A missing
profile or unreadable local state is an error; the command does not fall back to
another team or contact AWS.

Each valid deployment also includes a `cleanup` report sourced only from its saved
cleanup receipt, never a fresh inventory. Missing evidence has null resource
fields, not empty lists. Valid retained volume IDs and this exact deployment's
artifact prefix are shown; malformed identifiers/prefixes are suppressed with
`receiptState: "invalid"`. Remaining-resource diagnostics are not exported.
`cleanup.steps` contains exact argument arrays with the full network UUID,
selected zdn profile and absolute state directory, using `foundation` for
foundation-only requests and `devnet` for node requests. Local state paths must be
UTF-8 to represent these arguments exactly in JSON.

The inventory/receipt inspection steps are read-only. When local evidence has no
cleanup blocker, separate retain-data and delete-data proposals include `--yes`
and label `mutates`, `requiresAuthorization`, fresh-inventory and ownership/lease
prerequisites explicitly. They are **not permission to execute**; this report
always has `executionAuthorized: false`. Unresolved, incomplete or inaccessible
operations, pending updates, profile/helper mismatches and invalid/incomplete
cleanup evidence withhold mutation proposals. Never add `--reconcile` or a
lease-recovery ETag merely to bypass a refusal. Inspect fresh inventory and the
saved operation first, then obtain the required authorization.

Retention remains the default. `cleanup.cost` reports `estimateStatus:
"not-estimated"`, a null `monthlyUsd`, unchecked billing and explicit assumptions:
retained disks/artifact versions and the preserved shared backend, KMS key and
registry may continue to incur charges. No sizes, regional prices, resource
existence or actual bill are inferred from stale state. Retained disks do not
have a one-command restore/resume path. Following a successful retaining teardown,
an explicitly authorized `destroy --delete-data --yes` can delete the owned
retained data without recreating hosts; shared resources remain protected.

To retry a saved node deployment without its original configuration, Git worktree,
package manifest, source archive or caller artifact files:

```sh
zdn devnet up --saved NETWORK --profile devnet \
  --state-dir /path/to/local/state --yes
```

`NETWORK` is a full ID, unique prefix or unambiguous label in that profile's
scope. Explicit full IDs take priority over labels. Saved mode uses the locked
deployment receipt and staged artifact bytes, not the current directory. It does
not create a binding, recapture source, resolve a package or create another build
attempt. A complete untouched initial source preparation can instead resume its
original attempt, verifying image/ECR bytes before staging nodes. Any saved
dispatch requires `--reconcile`; quiesce the source controller even when the
attempt has not yet dispatched. See [initial build recovery](builds.md#4-cli-integration).
The selected profile must match the saved team definition and AWS profile name;
it cannot silently rewrite those inputs. When omitted, `--profile` defaults to
`devnet` in saved mode; selecting `--profile` without `--saved` is rejected.

Saved mode rejects explicit `--config`, AMI/zone, package/pin, chain/image/helper,
lightwallet artifact and reward-address overrides before state access. It also
rejects destroyed or foundation-only deployments, incomplete source builds
without a complete portable preparation, pending image updates, corrupt/missing
staged bytes and incompatible package helpers before backend/tool setup. It is
supported by `devnet up` and the `up` alias, not `devnet render`.

Uncertain saved operations still require `--reconcile`; missing or foreign
operation evidence blocks recovery. `--recover-lease-etag` still requires
`--reconcile` and an exact expired observed lease. `--yes` remains mandatory.
Neither selection nor discovery clears cancellation, a cloud lease, a Pulumi
lock or unresolved ownership. Existing fresh identity, ECR/policy, lease,
installation and readiness checks remain in the normal apply path. This is local
saved-state selection; use the explicit [controller handoff](#controller-handoff)
below to transfer it. This is not a resume path for already-destroyed retained
disks.

Run `devnet up --yes` again for an unchanged deployment and a fresh readiness
check. Add `--reconcile` after an uncertain Pulumi or install result. Each SSM
install has a durable journal. A lost send response is matched against the exact
saved request before polling; the CLI does not blindly submit a second command.
If AWS cannot establish which command was sent, recovery stays uncertain.
Cancellation requests remote cancellation and does not claim rollback.

A successful install or activation journal is reused; unchanged-up sends new
readiness observations. When recovery observes cancellation, it
reports that terminal result; run `up --yes --reconcile` again to record a new
attempt. A stopped producer gets a new activation attempt after any unknown
command is settled and fresh health is checked. A stopped or stalled controller
cannot pass the final gate just because an earlier start command succeeded.

Producer activation alone also permits one automatic fresh attempt after an exact
saved SSM invocation reaches `Failed`. Failure recovery and an explicit restart
after success consume the same single repeat allowance. Activation, reobservation
and restart share the original 720-second deadline, preserve command history, and
check cancellation and lease ownership before retrying. A restart does not grant
another failure retry or a fresh deadline. The host helper preserves durable
production intent even after partial effects. Cancellation, timeout, permission/transport errors,
invalid results and uncertain dispatch do not authorize this retry. Other host
operations retain their existing explicit retry behavior.

This version freezes the configuration, image, helper, artifacts, and install
script. It rejects changing them during recovery. Use a new binding for a new
experiment, or [an explicit image-only update](updates.md) for selected nodes
on existing hosts/disks. Pending updates must be resumed before `up` or teardown;
settled updates preserve their per-node revisions during unchanged `up`.
An already applied health-test foundation cannot be converted to a node cluster.
Legacy node-only requests without a saved block interval remain unscheduled.
Legacy requests with no `clientAccess` field, or `clientAccess: false`, keep their
original node runtime. `connect` and `endpoints` refuse those deployments. Use a
new devnet binding for client access; `--reconcile` does not migrate the request.

## Controller handoff

`devnet handoff` transfers a supported saved deployment to another workspace or
Linux/macOS controller, without cloud calls. Version one supports complete untouched
initial source preparations. Fully staged unlaunched node requests and completed
`devnet up` or image-update deployments with terminal, certain mutation histories
are also portable. Settled mixed-image deployments preserve their confirmed
per-node revisions; resuming on the receiver does not replay original installers.
It rejects incomplete preparation, unfinished update-source builds,
destroyed/cleanup state, unresolved or cancelled current operations, unsupported
interrupted updates, and updates to the lightwallet host. Keep unsupported
deployments on the original controller; never delete journals to bypass a blocker.

A narrow interrupted-update handoff is supported when the candidate and all
earlier revision history are saved and every target has its exact script and
validated SSM journal. Earlier updates and already-confirmed targets still need
terminal, certain attempts. An unconfirmed current target can retain its last
prepared, dispatched or running attempt, including a lost command ID and saved
cancellation intent; all earlier attempts must be terminal. The receiver uses
the same journal to recover/poll the exact request, never blindly resending an
uncertain command. The current update operation must be Running or Unknown with
a saved reference identifying this update UUID. Its outcome is preserved, not
relabelled success. The pending intent stays in the manifest; export does not
manufacture `completed.json` or confirm nodes. Untouched targets without saved
scripts/journals and unfinished update builds remain blocked. Update staging now
saves exact scripts and genuine Prepared journals for every selected target before
dispatching any host mutation. A crash after staging can therefore carry untouched
targets too; their original attempt IDs survive export/import and explicit resume.
An interruption partway through local preparation still blocks handoff until all
target evidence exists. Export/import never fabricate missing evidence. Repeating
preparation validates existing journals without rewriting them or creating retries,
including failed or uncertain attempts. Finish or reconcile unsupported states on
the source controller first.

Historical node, client-RPC and lightwallet observation journals may retain their
last unfinished/uncertain attempt. Handoff validates each exact observation
request, target, timeout and attempt history, preserving bytes and cancellation
intent without recovering, cancelling or replaying those observations. They are
not readiness evidence: apply/update uses new observation journals and fresh
validated responses. An old probe can still contend for a host lock; a blocked
fresh probe must not report readiness. Installation, capacity, activation and
confirmed update commands keep their terminal/certain requirements.

A crash after writing `completed.json` but before publishing finished deployment
state is portable when every target is already confirmed and that metadata
matches the exact pending intent with only `finished` set to true. Both saved
states are preserved. Import does not finish the update; explicit resume still
requires reconciliation and fresh node/service checks before publishing success.
Conflicting completion metadata blocks handoff and is never overwritten.

Each completed update saves `updates/UUID/completed.json` before publishing its
finished state. Handoff includes those intents, pinned revision artifacts,
update scripts and terminal command histories, validating each node's complete
old-to-new chain back to the original image. Missing, conflicting, cyclic or
forked history blocks handoff. An older controller's latest finished intent can
be materialized in the archive without modifying the source deployment; earlier
updates still need saved completed metadata. Older archives without updates
remain readable. Historical client observations must match the original gateway
or one of the confirmed update revisions, not arbitrary command hashes.

For staged deployments, an existing build workspace is omitted only after its
saved attempt and complete outputs verify as a successful build or reuse of the
staged image. A later, unrelated or uncertain build blocks export even if an older
deployment is ready.
The same check applies to source-build workspaces under supported updates;
their source snapshots and local source/build configuration files are not
transferred.
Resuming a saved source-built candidate uses its embedded build contract rather
than requiring an omitted sidecar or rebuilding. Any present sidecar must agree;
unfinished update builds still require their original recovery inputs.
Export and import reconstruct the expected installers and exact SSM commands and
timeouts offline; internally consistent archive hashes alone are insufficient.
A healthy lightwallet install needs no separate start journal; when one exists,
it must match the expected command and contain only terminal, certain attempts.

Untouched initial source builds are a separate narrow shape: no cluster/runtime,
initialized stack, outputs, operations or updates. The archive carries the complete
`source-preparation.json`, exact snapshot/input receipts and archive, private
chain/helper/optional-lightwallet inputs, and byte-preserved `build/attempt.json`.
Pre-upload, uploaded-unsent, uncertain dispatch, known running, terminal success
before image validation, and selected reuse states are supported. Raw job outputs
and download tempfiles are excluded, not converted into verified artifacts.
Missing records, failed terminal builds, incomplete publication, changed bindings
and held writer/build locks block export; no missing evidence is fabricated.
Receiver `up --saved` uses the same attempt and ordinary build/image/ECR checks
before allocating nodes. Transfer itself performs no AWS or readiness checks.

Export a new private tar and record the returned raw archive SHA-256:

```sh
zdn devnet handoff export NETWORK --profile devnet \
  --state-dir /path/to/source-state --output /private/network-handoff.tar
```

Transfer the archive privately and confirm its digest through a trusted channel.
It contains deployment identities, artifact bytes, installers, volume proofs,
supported recovery journals, and **all** operation history for this network,
including old cancellation flags. Treat it as sensitive controller state, not a
public release package. Credentials, local profiles, Pulumi workspace/diagnostics,
build scratch/output files, process ownership markers and OS lock files are not
exported.
The versioned inventory pins every payload's size and SHA-256; image layers and
remote Pulumi state remain in the team's existing services.

On the receiver, prepare the same team definition and an authorized local profile
through normal setup. Its AWS profile **name** must match the saved deployment:
that name is part of immutable volume-creation proofs and cannot be rewritten.
Credentials themselves stay on their respective machines. Choose an existing
configuration file in the receiving workspace, then explicitly attach:

```sh
zdn devnet handoff import --from /private/network-handoff.tar --sha256 SHA256 \
  --network-id FULL_NETWORK_UUID --profile devnet \
  --team-id TEAM --account-id 123456789012 --region us-east-1 \
  --config /receiving/workspace/devnet.yaml --state-dir /path/to/receiving-state
```

Import checks the raw pin before parsing, rejects undeclared/duplicate/unsafe tar
entries, verifies artifacts and recovery evidence privately, and publishes the
deployment before its binding/operation ledger. The new binding uses the receiving
config path, Git worktree and branch, not the sender's absolute paths. The receiving
configuration must resolve its own valid local binding context; it does not
replace the frozen workload configuration in an initial preparation. Saved resume
does not open that preparation's original checkout path. Local state must remain
outside the configuration directory/worktree. Import requires an
unused context and network ID and never overwrites existing state, even an
identical prior import. A crash after directory publication but before ledger
publication can leave an undiscoverable orphan; import fails closed on that path.
Preserve it for inspection or select a fresh local state directory; do not remove
state while another writer might be using it. Atomic no-replace publication uses
Linux `renameat2(RENAME_NOREPLACE)` or macOS `renameatx_np(RENAME_EXCL)`;
unsupported filesystems fail closed without an overwrite-prone fallback. The
staged deployment writer lock moves with the directory and remains held through
ledger publication. This client support does not enable Linux host runtimes on Mac.

Import does not start a deployment, reserve resources, grant IAM authority or
clear a cloud/Pulumi lock. Stop using the source controller for mutations after
handoff; this is a copy, not revocation of its access. Resume deliberately with
`devnet up --saved FULL_NETWORK_UUID --profile devnet --state-dir /path/to/receiving-state --yes`.
For an initial build, keep the source controller quiescent before receiver resume,
even if it has not submitted yet. Add `--reconcile` if dispatch was recorded;
unknown submission must recover the same job, never start a second one.
For a supported interrupted image update, use
`devnet update FULL_NETWORK_UUID --resume UPDATE_UUID --reconcile --acknowledge-storage-compatibility --profile devnet --state-dir /path/to/receiving-state --yes`
instead. Confirmed nodes are reobserved; saved commands settle through the same
journals rather than being blindly submitted again. An existing cloud lease
still requires the normal ownership/expiry and explicit recovery checks.
The existing fresh identity, ECR, policy, ownership, lease and readiness checks
still apply.

## Tear down

```sh
zdn devnet destroy my-feature --yes
```

This removes hosts, networking, and the network's client-session documents,
retaining chain disks, the optional lightwalletd cache disk, and deployment artifacts.
Retained data continues to cost money. Add `--delete-data` to delete the recorded,
owned disks and all versions and delete markers under this deployment's artifact
prefix. The shared backend, IAM policies, registry, reservations, and operation
history remain. A failed cleanup does not report success.
The protected participant role remains in its administrator stack. It cannot
connect after the hosts and session documents are removed.

Pulumi can retain a stale Elastic IP association after deleting the NAT gateway.
If teardown stops there, retry `zdn devnet destroy my-feature --yes --reconcile`
after NAT deletion completes. Reconciliation refreshes the saved state. Keep `--delete-data`
on the retry if the original request included it.

Version cleanup requires `s3:DeleteObjectVersion`, which the generated deployment
policy grants only under the team's artifact prefix. It does not permit deleting
versions of Pulumi state, leases, reservations, or administrator state. Previously
provisioned teams must repeat administrator setup before using this permission.

## Access and tests

Hosts can read the team's deployment artifact prefix and pull images from the
team's ECR namespace. They cannot read Pulumi state, leases, or reservations, or
modify IAM. The node runs without root privileges; UID-specific firewall rules
block its access to instance metadata even with Docker host networking. Root SSM
services retain the instance profile for installation.

The pull policy follows [ECR's authorization requirements](https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policy-examples.html).
Artifact decryption accounts for the bucket ARN encryption context used by
[S3 Bucket Keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html),
while S3 reads stay restricted to the artifact prefix. The SSM journal uses
[Run Command](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html)
with a unique request comment and exact request matching.

Offline tests cover image/config bytes, rejected platforms, source-independent
staging, CLI validation, constrained Pulumi resources, disk ownership and
retention, S3 checksums and lost replies, generated host code with fake tools,
SSM interruptions, lease/cancellation progress, and phase recovery. They do not
substitute for real Docker behavior, AWS policy enforcement, P2P propagation,
reboots, or chain/payment acceptance.
The [connection tests](testing.md) add proxy method and cookie checks, process cleanup,
endpoint-file validation, participant-policy fixtures, and grant recovery.
