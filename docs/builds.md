# Source-to-image builds

Captured local Zakura source feeds a native Linux x86-64 CodeBuild
job and then the private-node deployment, with exact-image reuse,
persistent intermediate layer caches and recovery of the same saved build.
A successful image build does not prove that a node starts or that wallet payments work.

Build execution now requires a pinned native exporter. Old receipts without that
selection remain readable for inspection and cleanup, but cannot poll, resume,
cancel, reuse or submit through the build executor. Do not delete or rewrite a
legacy receipt to grant new authority; inspect its actual job and settle/remove
the disposable test resources separately.

## 1. Build contract

`zdn-build/v1alpha1` binds the complete source tar SHA-256 and byte length, full
Git revision, repository Dockerfile/context/runtime target, `linux/amd64`, and
the exact [required image capabilities](image-contract.md). The tar hash includes
captured dirty working files; the revision alone does not identify those files.
Paths must be relative, with alphanumeric, dot, underscore or hyphen components;
parent traversal, missing Dockerfiles, and recipe paths through links fail.
Archives are limited to 512 MiB and checked locally before any AWS write.

The result binds the contract fingerprint to an image record with the immutable
single-platform image digest and configuration digest. The adapter checks source
provenance, repository, manifest bytes, config bytes, platform and runtime defaults,
then independently reads the exact child digest from ECR. Capability declarations
and source metadata are not attestations or evidence of running-node behavior.
The existing host inspection/bootstrap/readiness checks still apply.

## 2. Administrator resources

Repeat administrator `setup bootstrap` with the team's original role settings
to apply the updated protected Pulumi access stack. This adds:

- A dedicated private, ownership-enforced S3 bucket with public-access blocking,
  versioning, bucket-default AES256 encryption and a TLS-only policy. It is separate from the
  team's Pulumi/S3/KMS state and has no forced deletion.
- An immutable, scanned ECR repository in the existing `zdn/TEAM/` namespace.
- A native x86-64, privileged Docker CodeBuild Standard 7.0 project with a
  team-scoped S3 cache, no automatic artifacts, a failing default buildspec,
  a two-hour build limit, a one-hour queue limit, and scoped CloudWatch logging.
- A CodeBuild-only service role restricted to reading source versions, writing
  job results, reading/writing the cache prefix, pushing/reading this repository,
  and writing this log group. Bucket metadata reads and cache-prefix listing
  support caching.
  It has no node, state-backend, KMS-state-key, or IAM permissions.
- A deployment policy permitting submission, polling and cancellation of this
  project, project-scoped recovery listing, source upload, result/index reads,
  encrypted reuse-index publication, and repository manifest reads. It also
  permits listing the exact build bucket so S3 reports a missing reuse index as
  `NoSuchKey`, not `AccessDenied`; GetObject provides no prefix condition context,
  so this exposes names throughout that bucket without granting object reads.
  It cannot change the executor or its service role. Host runtime policies and
  state-bucket permissions are unchanged.

Names are deterministic from team, bootstrap ID, account and region. The adapter
refuses a missing or incorrectly configured project before uploading source.
Externally managed roles do not create owned resources through setup; their
administrator must provision the equivalent resources and policy. See
`BuildInfrastructure::for_team` and `resources` for the exact naming and graph.
Build storage, images and logs are team-owned; network teardown does not delete
them. [Explicit team removal](removal.md) handles the originally owned build
infrastructure and receipted data after networks/grants are removed; it refuses
active or unreceipted builds and unexplained images/data. External resources
remain the administrator's responsibility.
Trusted developers can supply build commands and must treat the build role's
source/result/image access as shared within their team, not as tenant isolation.

## 3. Job adapter

The adapter privately copies and verifies the tar, uploads it with a server-checked
SHA-256, and requires an S3 version ID. Its inline buildspec retrieves that exact
version, verifies the hash again, extracts it, builds the runtime target natively,
and pushes a unique attempt tag. Buildx disables provenance/SBOM indexes so the
result can meet the single-platform image contract. New attempts use exporter
protocol `zdn-build-export/v1alpha2`: Buildx pushes directly to ECR without loading
the image into Docker, a separate push, or a whole-image `docker save`. The recipe
uses `jq` (included in CodeBuild Standard 7.0) to select the config digest from
the registry manifest, then requests its download URL using the existing
repository-scoped `ecr:GetDownloadUrlForLayer` permission. The native exporter
checks the manifest and returned digest before downloading the exact raw config
with the existing bounded HTTPS downloader. Manifest/config digest, size,
platform, provenance, capability and runtime-default checks remain unchanged;
the exporter does not validate layer contents. Presigned URLs stay in private files
and are excluded from exporter transport errors.

Only the current exporter protocol is supported; old build attempts cannot be
migrated or executed.

The exporter and source uploads share the bounded AWS batch helper. Both private
copies and requests are validated before either upload starts. Each confirmed
checksum, encryption mode and version ID is saved on the controller thread even
if its peer fails; resume uploads only the missing peer. Upload or receipt/progress
errors prevent `StartBuild`. No new executor or retry authority is introduced.
After the result establishes the exact image identity, manifest and config reads
share a batch with separate private output files and bounded streaming reads.
Manifest/config verification and independent ECR comparison still precede local
publication. The result read and ECR verification retain their identity/content
dependencies; exact-contract reuse and changed-source layer caching are unchanged.

The versioned, private `build/attempt.json` binds the team, project, repository,
contract, attempt UUID, uploaded S3 version, submission state and build ID.
An exclusive file lock prevents concurrent dispatch. Submission intent is durable
before `StartBuild`; its short-lived idempotency token is not the recovery mechanism.
Known jobs resume by ID. An unknown start is reconciled through bounded, paginated
project history and exact buildspec/project/ARN matching. The scan must finish with
exactly one match; no match, ambiguity or incomplete history never authorizes
another submission. Recovery is bounded to 100 pages and five monotonic minutes.
Polling has a separate monotonic deadline. Cancellation and timeout recheck job
ownership before requesting `StopBuild`; that request is not a claim that termination
has completed. Unknown AWS outcomes, terminal build errors,
unknown status, missing outputs and invalid images stop before node allocation.
Verified files are published locally only after validation and the ECR check.

The adapter's `run_with_progress` API reports sanitized observations after durable
attempt writes. It exposes the attempt UUID and contract fingerprint, whether
source upload/submission/build identity is recorded, a reuse candidate UUID, and
the fixed job outcome. It excludes source versions, raw provider IDs, buildspecs
and diagnostics. `imageVerified` becomes true only after the result files and
independent ECR check pass, not when a job says `SUCCEEDED` or an index selects a
candidate. Resuming rechecks verification rather than trusting a previous event.
Observer failure stops later effects without erasing intent or automatically
stopping/resubmitting an existing job. A failure after saved submission intent can
therefore require reconciliation even when no request was sent. The original
`run` API retains no-op reporting. Source `up` now uses these observations for
the [machine contract](automation.md#implemented-lifecycle-execution-events):
JSONL/progress files receive `build-observed` records, and terminal JSON/JSONL
retains the latest sanitized attempt under `data.build`. Build attempts do not
invent lifecycle operation IDs; node provisioning still starts only after the
image is verified and staged. Machine formats grant no build authorization.

Before a new upload or job, a bounded `images/CONTRACT_SHA256.json` index can select
a prior result attempt. Only typed S3 `NoSuchKey` is a cache miss. The index is
just a candidate pointer: result contract, provenance/capabilities, manifest/config
bytes and the exact ECR digest are checked again. Reuse does not submit work or
rewrite the index. After a new verified build, conditional first-writer-wins
publication preserves an existing bound pointer. Corrupt indexes and permission
errors fail rather than silently start billed work. Results and indexes are shared
team data, not attestations or isolation between trusted developers.

Buildx's Docker-container builder imports/exports a local `mode=max` layer cache,
persisted by CodeBuild in the dedicated S3 `cache/` prefix. Namespaces bind the
team infrastructure, native platform, executor/cache format and recipe; source
changes can reuse compatible dependency/compiler layers. BuildKit content keys
invalidate changed Dockerfile/toolchain steps. Each attempt has an immutable cache
key and a compatible fallback prefix.
Missing caches build cold. New attempts set cache export `ignore-error=true`, so
an optional cache-export failure does not fail an otherwise successful build.
Compilation, registry push and other build failures do not trigger a second
blanket `--no-cache` build. Missing cache imports can be ignored by BuildKit, but
arbitrary corrupt/incompatible cache failures are not promised to recover
automatically.
Only completed cache exports are promoted after image/result checks. This does
**not** persist arbitrary Docker
`RUN --mount=type=cache` contents. Cache objects can
accumulate; retention remains an administrator responsibility.

Bucket-default AES256 applies to uploads without an encryption header; it does
not dictate CodeBuild-managed cache encryption. [CodeBuild uses AWS-managed KMS
keys by default for caches and build artifacts](https://docs.aws.amazon.com/codebuild/latest/userguide/security-encryption.html).
The bucket policy permits headerless cache uploads and explicit `AES256` or
`aws:kms` encryption, denying other explicit encryption values only under the
exact `cache/` prefix. TLS remains required throughout the bucket. Source and
reuse-index uploads still require explicit AES256 through their identity policy.
This adds no KMS or IAM grants and leaves the state/backend KMS boundary unchanged.

There is no automatic resubmission of terminal or unresolved attempts. Preserve
`source-snapshot/`, `source-build-inputs.json` and `build/`; do not delete receipts
to retry paid work. Missing, malformed and legacy receipts fail closed and require
manual job inspection, not automatic migration. [Selected-node updates](updates.md)
reuse this build path without replacing hosts or disks. Changed source must use
the explicit update command, not recovery through `up`.

## 4. CLI integration

Prepare a node-only local-source config with
`zdn init --source /path/to/zakura` (the default `--service-preset node-only`).
Select the repository recipe at init with `--dockerfile PATH --build-context PATH`,
both relative to the captured Git root and requiring `--source`. Defaults remain
`docker/Dockerfile` and `.`; the selected research monorepo instead requires
`--dockerfile node/zakura/docker/Dockerfile --build-context .`.
`zdn devnet render` captures
a temporary local snapshot and reports the contract and costs without contacting
AWS. This is a build preview, **not** a saved node infrastructure plan; `up`
captures source again. A native Linux helper and saved chain inputs are still
required; this deliverable does not distribute either artifact.

After reviewing the contract and administrator setup:

```sh
zdn devnet render
zdn up --yes --ami-id ami-REPLACE --availability-zone us-east-1a \
  --manifest manifest.json --bundle chain.tar --host-helper ./zdn-linux-x86_64 \
  --reward-address YOUR-TESTNET-REWARD-ADDRESS
```

For local source, omit `--image-record`, `--image-manifest` and `--image-config`;
the job supplies them. `zdn devnet up` and `zdn up` use the same path. Pinned-image
configs still take all three image inputs and do not submit builds. Optional
lightwalletd still requires its three separately pinned image inputs.

The first source `up` validates local chain/helper inputs and captures source.
Before credentials or submission, it saves a complete `source-preparation.json`
record, private chain/helper/optional-lightwallet copies, and the original build
attempt. The record binds the configuration, build contract, reward address,
snapshot and input receipts to this deployment's spec, team and owner. It is not
a launchable node request or evidence of a verified image. Only after ordinary
build/reuse and image/ECR verification does `up` freeze the node request and enter
the leased Pulumi/SSM provisioning path.

After interruption, the same `up --yes` command with unchanged caller inputs
reuses the saved archive and attempt. Alternatively, a complete preparation now
supports `devnet up --saved NETWORK --profile PROFILE --yes`, without the
original checkout, configuration or caller artifact files. Any dispatched attempt
requires `--reconcile` in saved mode. Source controllers must be quiescent before
receiver recovery, including pre-dispatch states; copying state does not revoke
their access. [Controller handoff](private-devnet.md#controller-handoff) transfers
this narrow initial state without AWS calls, preserving the exact attempt UUID,
source version, reuse pointer, dispatch intent and known job/terminal state.
Uncertain submission recovers the same job, never blindly resubmits it.

Missing, changed or incompletely published preparation/receipt bytes fail closed,
without recapturing source or creating a replacement attempt. Old controllers
without a complete record, failed terminal builds and unfinished source-update
builds are not eligible for this handoff. Unverified build outputs are excluded
and fetched/verified again on resume. Subsequent staged node operations continue
to use their immutable saved request rather than working files or another build.

## Offline verification

See the contributor [test coverage notes](testing.md#subsystem-coverage-notes).
