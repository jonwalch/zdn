# External deployment controller (local implementation)

This is the Linux-only operational controller branch for the public contracts in
[external-chain-offline.md](external-chain-offline.md). For the opt-in Linux TPQ
profile and complete starter walkthrough, begin with [TPQ preview](tpq-preview.md).
This contract document is not release qualification or permission to run a new
live test. Ordinary deployments still use their original in-process contracts
and omit the external saved-deployment field. Mac ordinary behavior is unchanged;
external execution remains Linux-only.

R8 (2026-11-01) passed the actual two-node AWS source-build/deployment journey in
55.85 minutes: one funding, v5/v6/restored-v6 payments, one retained node-only
restart per node and original gateway continuity. Staged/final independent
cleanup passed 229/228 observations across 57 protected keys and 17 regions.
These are selected analog PAY-01, happy-path PAY-02, WAL-08, JRN-06 and CLN-01/03
subcases of beta plan v1.0 / 2026-10-23, SHA-256
`20bc7e52be2df2d78706d5e4c453bfa91e42feefcad83d550c5a1abc31a499d2`.
No lost-reply injection, image update, host reboot or handoff was tested in R8.
Full beta and clean-user release-profile rehearsal remain pending. Historical
development evidence does not qualify rebuilt or post-processed release bytes.

## Public selection and commands

There are two explicit first-launch branches. A completed image uses the
signing-free eleven-slot artifact set produced by `zdn external stage`.
Alternatively, an external source config uses the seven-slot public package,
an explicit trust file, Linux ZDN host helper and native CodeBuild exporter to
capture, build/reuse and launch its **first** image. Neither branch discovers a
companion on PATH. The config's external package/selection pins must agree;
an installed executable or package self-declaration never grants trust.
`--external-trust` is the `CoreTrust` JSON object: `package` and `executable`
byte/hash pins plus `adapterSelectionSha256`. No wallet/key material is accepted.

The TPQ starter supplies `external.yaml` and `core-trust.json.in`. The trust
shape is exactly `{"package":{"bytes":N,"sha256":"HASH"},
"adapterSelectionSha256":"HASH","executable":{"bytes":N,"sha256":"HASH"}}`.
Replace `N`/`HASH` only after independent review of the package and authenticated
distribution executable. Package self-declarations and co-downloaded checksums
are not publisher authentication. The adapter selection, native fingerprint,
raw package hash and semantic config fingerprint are distinct identities.
Do not use the raw YAML file hash as `Config::fingerprint`.

```sh
# First source image: external.yaml selects node.source.path and node.build.
# The public directory has package.json, descriptor.json, native-rules.json,
# wallet-profile.json, seed-blocks.bin, host-adapter and compiled.json; NO image
# triple is needed. This captures/prepares locally and makes no cloud call.
zdn devnet render --config external.yaml \
  --external-public-directory /absolute/public-package \
  --external-trust /absolute/reviewed-trust.json \
  --external-build-helper /absolute/zdn-linux \
  --host-helper /absolute/zdn-linux --reward-address TESTNET_ADDRESS \
  --ami-id AMI --availability-zone ZONE

# Start the exact captured preparation (billed CodeBuild/reuse then deployment).
# Render is optional: the same explicit inputs work directly with devnet up
# instead of devnet render, adding --yes. Once prepared, use saved recovery:
zdn devnet up --saved NETWORK --reconcile --yes

# Save immutable local inputs and render only; no AWS calls.
zdn devnet render --config external.yaml \
  --external-request /absolute/staged/external-request.json \
  --external-request-sha256 TRUSTED_REQUEST_SHA256 \
  --external-directory /absolute/staged \
  --external-native-port 18233 --reward-address TESTNET_ADDRESS \
  --ami-id AMI --availability-zone ZONE

# The same explicit inputs select real deployment/install dispatch, not refusal.
# This is a billed operational command; do not run without approval.
zdn devnet up --config external.yaml \
  --external-request /absolute/staged/external-request.json \
  --external-request-sha256 TRUSTED_REQUEST_SHA256 \
  --external-directory /absolute/staged \
  --reward-address TESTNET_ADDRESS --ami-id AMI --availability-zone ZONE --yes

# Recovery opens only saved immutable inputs; it never recaptures a checkout.
zdn devnet up --saved NETWORK --reconcile --yes
zdn devnet status NETWORK
zdn devnet health NETWORK --wait --timeout-seconds 120

# Explicit targets, forward-only compatibility consent, no automatic rollback.
zdn devnet update NETWORK --node node-2 \
  --image-record image.json --image-manifest image-manifest.json \
  --image-config image-config.json --acknowledge-storage-compatibility --yes

# Source alternative: capture once, bind compiled requirements, then reuse the
# existing native CodeBuild exporter, exact reuse identity and recovery journal.
zdn devnet update NETWORK --node node-2 \
  --source-config candidate.yaml --build-helper LINUX_EXPORTER \
  --acknowledge-storage-compatibility --yes
zdn devnet update NETWORK --resume UPDATE_UUID --reconcile \
  --acknowledge-storage-compatibility --yes

# No companion, wallet, local source checkout or artifact execution is needed.
zdn devnet destroy NETWORK --reconcile --delete-data --yes
```

The native UDP port defaults to 18233 and is restricted to exact cohort /32s.
Ordinary TCP rules are unchanged. External production cadence is 1..=3600
seconds, and only node-1 is scheduled. External wallet/faucet/lightwallet
services remain refused; wallet authority and payment journals stay outside ZDN.
macOS ordinary support is unchanged; external execution is not supported there.

## Saved contracts and recovery boundaries

`Deployment.external` is `zdn-external-deployment/v1`, mutually exclusive with
ordinary cluster/runtime/foundation authority. It retains the canonical immutable
request pin, native port, cohort size and public reward address. Structural
ownership and destroy do not load an adapter executable, even if installation or
an image revision failed. Destruction still requires the existing reservation,
lease, Pulumi ownership checks and explicit deletion/reconciliation consent.

`Deployment.external_source` optionally retains
`zdn-external-source-preparation/v1`, omitted from ordinary receipts. The outer
`external-source-preparation.json` and exact atomically published copy
`external-source/external-source-preparation.json` bind saved owner/spec/team,
config/trust, compiled requirements, reward/native port and eight public/helper
slot pins. `external-source/public/` freezes those bytes, `source-snapshot/`
freezes `source.tar` and `receipt.json`, and `build/` retains the existing native
attempt/exporter/submission/reuse/result journals. Requirements are bound before
native preparation or any billed effect. `SourcePreparation::read` and
`verify_local` are no-execution ownership/admission APIs. Saved up recompiles only
the authenticated snapshot; it never recaptures the caller's checkout or opens
the original exporter. A dispatched build requires explicit reconciliation.
Complete image proofs materialize the normal external request before any host
deployment; an incomplete source preparation cannot become an ordinary
foundation launch. Cleanup re-observes only known build jobs and needs no
companion, even if source installation or publication failed.

`external-evidence.json` records the request/cohort/inventory pins, exact previous
inventory snapshot, one pending identity edge, final manifest pins and per-node
confirmed image revisions. A crash between create-only identity publication and
evidence replacement may complete only that exact pending member; unrelated
additions, changes or losses refuse. No final runtime is rendered before all
native public identities are authenticated through exact durable SSM requests.

The existing new-volume proof and sealed phase-one ownership freeze before
identity provisioning. Scripts and all eleven slots are uploaded through the
existing authenticated immutable delivery path. Only external cloud-init adds
the distribution's bubblewrap package; ordinary prerequisites stay unchanged.
Missing or unusable trusted sandbox prerequisites still refuse; namespace or
security restrictions are not disabled. Final activation reuses the
host's bootstrap renderer and fixed-operation renderer. Fresh cohort readiness
precedes the separate durable producer-start command; final readiness additionally
requires current producer ownership/cadence and the exact gateway service hash.

`external-updates/UUID` retains image proofs, exact per-node host requests and,
for source mode, the captured archive/config, requirement-bound build contract
and existing build receipts. Resume does not reopen caller files. Update preflight
requires exact saved EC2 identity, ownership tags, VPC/subnet/private IP and sole
recorded EBS attachment; host revisions reuse the existing maintenance/journal
algorithm. Original disk/key/helper/cohort/config/producer authority never changes.
Completion publishes current `client-endpoints.json` after fresh readiness.
Destroy reuses the native build-removal admission without companion execution;
an active or unknown source build remains blocked until its terminal outcome is
independently known, not silently abandoned or resubmitted during cleanup.

Connection callers should use
`foundation_live::external::endpoint_file(deployment, receipt_directory)` for
the current confirmed revision. It checks pinned evidence and emits
`zdn-external-endpoints/v1` with the exact service-bound finite body class, without
executing the companion. External health uses fresh observation-only SSM UUIDs,
bounded API deadlines and no lifecycle backend, tools installation, mutation
lease or service-start action. These are readiness observations, not payments.

## Offline qualification controls

`zdn external control-script --manifest ORIGINAL --request REQUEST --output NEW`
renders only. It creates a new private script and a public request/script-pin
receipt with `dispatched: false`; it never overwrites or executes the script,
opens an AWS session, or grants arbitrary shell/RPC access. Both inputs use their
canonical encoding. The original manifest selects the pinned host executable;
the request separately pins the expected effective revision, including updates.

The Linux helper capability `zdn-external-qualification/v1` accepts a canonical
request containing `schema`, RFC4122 v4 `id`, `runtime` byte/hash pin and a fixed
`action`. Available actions are:

- `read`, with `query.kind` of `tip`, `transaction` (canonical `txid`), or `output`
  (`txid`, unsigned `index`). Responses contain bounded projections, never whole
  transactions/blocks. Transaction metadata includes exact raw-byte digest/size;
  missing transaction is distinct from RPC failure. Null output is not proof
  of a confirmed spend. Use the existing participant gateway for raw bytes.
- `gateway-identity`, on node-1 only: MainPID, procfs start ticks, boot ID and
  authenticated executable pin, rechecked during observation. Comparing these
  observations supports continuity; isolated observations do not prove it.
- `stop-producer`, only on the designated producer; it leaves the node up.
- `produce`, with `blocks` 1–20, positive absolute `height` and `seconds` 1–600.
  It stops the scheduled producer and uses the same durable generation journal.
  New generation stops at the count, height or monotonic budget. Pending work
  is still reconciled, not replayed or discarded at a limit; these limits are
  not hard wall-clock termination of an in-flight request/reconciliation.
- `restart-node`, a retained same-revision stop/start with fresh readiness;
  production stays stopped. It does not reinstall, bootstrap or change keys.

Host dispatch authenticates the installed original and effective runtime,
retained mount/native identity/config/bootstrap and units. Qualification and
installation serialize with image maintenance through the existing update lock;
restart releases only the installation lock needed by child unit actions.
Mutating requests publish a durable dispatch marker before effects. A completed
UUID returns its original bound receipt; a dispatched UUID without completion
refuses automatic replay. Preserve its records for reconciliation. Responses
bind the request, runtime, deployment, node and native inventory and remain at
most 16 KiB; the existing 20-KiB SSM output ceiling is unchanged.

Only external node units lose automatic producer activation on node start. Only
external gateway units lose node stop/restart propagation, retaining startup
ordering and hardening; image updates still stop the gateway explicitly.
The gateway can therefore remain alive and report unavailable during a node
outage, then reread replaced credentials. Unit text and uninterrupted loopback
gateway coverage do not qualify real systemd or real-node restart behavior.

Named external endpoint export/connection now uses the current confirmed
external evidence and rejects destroyed/unresolved deployments, pending updates,
changed runtime/evidence and stale endpoint bindings before cloud dispatch.
Explicit exported endpoints and ordinary deployment behavior are unchanged.

## Saved selected-node controls and first-launch limits

Linux `zdn devnet control NETWORK --node node-2 --action action.json
--prepare-only` freezes a typed action and script locally, returning its UUID,
request pin and runtime pin with `dispatched: false`. It requires neither cloud
credentials nor managed tools. For example, `action.json` can contain
`{"kind":"read","query":{"kind":"tip"}}`. Other read queries are
`block-hash` with `height`, `transaction` with `txid`, and `output` with `txid`
and `index`. No arbitrary RPC or shell operation is admitted.

Executing that exact frozen selection uses `zdn devnet control NETWORK
--resume CONTROL_UUID --reconcile --yes`. **This crosses the AWS boundary and
requires separate authorization.** New selections can also execute directly
with explicit node/action and `--yes`. Current complete cohort/runtime evidence,
owned instance/volume preflight, reservation, exclusive lease and durable SSM
transport remain mandatory; these controls do not run Pulumi or build/install
an image. Execution currently requires the existing managed-tool installation
through the shared backend constructor. Resume opens no caller action file.
The operation and host request share one UUID. Unknown mutations stay fenced;
fresh selected-node reads may observe them without clearing their uncertainty.
Completed results are reused only after local binding validation. Handoff
preserves control intents, scripts, operation receipts and command journals,
including observations of older confirmed image revisions.

For auditable selection, use the root `--format json` option and save each
preparation result to a new private file. Its `data` contains `controlId`,
`networkId`, `nodeId`, `request`, `runtime`, `intent` and `dispatched:false`.
Review `intent.request.action` and those pins before resuming the returned ID.
Execution returns `data.observation` bound to the original request pin, effective
runtime pin, deployment ID, node ID and native inventory. ZDN checks these
bindings even for a saved completed result. Inspect `observation.result`; exit
zero, the outer control ID or `paymentQualification:pending` is not confirmation
of a payment. Fresh observations need new read IDs, not replay of an old read.
Prepare-only does not dispatch, and `--resume` never opens a replacement action
file. Keep the original ID on an uncertain mutation; never delete its fence.

External config `chain.productionLimits: {maxHeight: 121,
lifetimeSeconds: 21600}` pins an optional absolute height and first-activation
lifetime before launch. Lifetime must be 1–21600 seconds (six hours) when
explicitly set;
this is not a default producer expiry or a global ZDN lifetime. The authenticated
producer activation publishes one retained, create-only deadline before startup;
service/image restart never renews it. Scheduled and qualification production
intersect their invocation limits with these immutable ceilings. The shared
producer accepts an explicit per-invocation duration up to 21600 seconds too,
so scheduled production can use the whole remaining window;
neither limit supplies a duration when omitted. Missing,
expired or future activation fails closed for new generation, while existing
pending generation can still reconcile. Deadline expiry cannot retract an
already-dispatched RPC. Omitted limits preserve legacy serialized bytes and
behavior; a qualification plan requiring ceilings must explicitly supply them.

The research cloud-wallet composition uses one supplied managed node-1 socket
for both wallets, bounded per-node controls and local signed-byte inspection.
It does not provision resources, create tunnels or clean up, and excludes
opposite-peer submission/raw node-2 transaction evidence rather than fabricating
a second participant gateway. Live dispatch is disabled unless explicitly opted
in by its caller; that flag does not grant AWS approval.

**Remaining for release qualification:** candidate-specific distributed executable
and ABI checks, a clean-user rehearsal from the final assets/instructions, and
all excluded fault/update/handoff/full-beta gates. R8 established real host and
node/gateway continuity only for its pinned development candidate, not future
release bytes. Every new live run still needs scoped approval and resource/cost
bounds. Do not execute scripts manually to bypass saved admission/journals.

## Validation and remaining integration boundaries

`tests/external_controller.rs` covers ordinary-byte omission, scoped UDP,
structural source ownership/requirements/atomic-publication crash recovery,
paired image/source update operation inputs, native-inventory crash-edge,
host-action/readiness binding and journaled lifecycle/interrupted-install/
missing-companion teardown coverage. The lifecycle fixture also invokes real
offline `devnet list` with an empty environment/PATH, checking both external
request kinds and exact devnet cleanup commands/retained-prefix admission.
These fixture tests do not qualify cloud, node, proof or live workloads.

First-source builds and source image updates both use the existing ZDN native
build lifecycle; no AWS/Docker lifecycle bypass was introduced. Portable external
handoff and top-level plan/capability/list/connection presentation are wired to
the external deployment family. Team removal includes
`removal::external_build_evidence` in its existing local evidence inventory, so
source/update build journals join existing S3/ECR cleanup ownership. The normal
offline suite, formatting and Clippy must cover these paths before publication;
source presence and fixture success are not live qualification or authorization.
