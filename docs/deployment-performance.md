# Deployment concurrency and performance limits

ZDN overlaps independent node installation, readiness, build transfers, backend
hardening and cleanup inventory. This page describes scheduling, recovery and
resource bounds, not measured performance results or an AWS provisioning-time
guarantee. For first-time setup, follow the [preview guide](preview-start.md).

## Scheduling and safety boundaries

1. **Resource creation is dependency-driven.** Pulumi schedules
   independent resources concurrently. Hosts and disks do not form a per-node
   dependency chain. NAT/private-route readiness precedes host startup; images
   verify before node allocation; preview and ownership checks precede
   infrastructure effects. These gates apply regardless of concurrency.
2. **Initial installs overlap boot preparation.** ZDN prepares exact volume
   authorizations, scripts and uploads while cloud-init proceeds. It polls fresh
   hosts' SSM availability in bounded groups of up to 50 IDs under one separate
   15-minute availability deadline. Each online host is admitted without waiting
   for the last host; offline hosts consume no execution slots or command
   budgets. Already submitted commands recover without an availability
   gate. Optional lightwallet capacity preparation retains its selected-host
   availability requirement before rendering capacity-bound installers.
   A single controller interleaves the existing SSM protocol with up to four
   outstanding remote commands, filling free slots rather than waiting for an
   entire wave. Image pulls, bootstrap and node startup can overlap across hosts.
   Small AWS submission/status calls are synchronous; one controller writes
   the lease.
3. **Fresh node observations overlap.** Per-node observation journals track each
   check. Every node's original install identity, active image/update, chain
   readiness and producer contract must validate before producer activation
   and optional service installation proceed.
   Service actions sharing a host lock and selected-node rolling updates retain
   their existing ordering.
4. **Independent cleanup inventory overlaps.** The shared AWS CLI adapter uses a
   rolling pool of at most four calls, retaining input-ordered outcomes and
   joining every local worker before returning, including on failure. It covers
   the 12 team EC2 inventory families and nine network families. Each tagged
   network family is scanned once, regardless of node/cache-disk count; saved IDs
   are reconciled individually so one missing ID cannot hide another resource.
   Exact observations replace stale tagged identities; a NotFound response never
   erases contradictory tagged evidence. An API error, malformed/paginated result
   or remaining resource still prevents deletion.
5. **Artifact cleanup is bounded.** Network artifact cleanup lists up to
   50 versions/markers per page. The CLI projects only truncation
   and exact key/version identities, keeping even long-key responses bounded.
   Normal pages use one deletion request; long escaped identities are split by
   serialized size to stay below the OS per-argument limit. ZDN checks partial
   errors after every scoped deletion and relists to prove emptiness.
   No shared state prefix is purged. Team backend purges still acknowledge old
   versions before deleting current versions/markers.
6. **Independent build transfers overlap.** Private source/exporter copies
   validate before either upload. Each confirmed version is durably recorded,
   including when its peer fails. StartBuild requires both successful uploads.
   After the result establishes the expected image identity, manifest/config
   download together into separate bounded files; bytes validate before ECR
   comparison/publication.
   [Exact-image reuse and uncertain billed-job recovery](builds.md) still apply.
7. **Unprotection requires exact ownership.** Every protected administrator
   resource URN validates before a batched state-unprotect invocation. ZDN does
   not use `--all` or concurrent writers to one Pulumi checkpoint. Reconciliation
   and fresh absence checks are required before stack removal.
8. **Backend hardening and settings reads overlap.** After verifying bucket ownership
   and region, ZDN sets public-access blocking and bucket-owner-enforced ACL controls
   together. Both must succeed before keys or state writes.
   These idempotent operations can resume on the original owned bucket.
   Bucket/KMS creation, policy refusal and key/encryption validation are ordered;
   an uncertain create is never blindly retried. Backend preflight batches its five
   independent S3 settings reads after ownership verification. All five settings
   and the key must still validate before the caller proceeds.
9. **Immutable artifact delivery is pipelined.** All staged deployment inputs
   verify before remote effects. Independent HEAD checks and conditional PUTs
   run in batches. Every candidate is reconciled by checksum, byte length,
   encryption and KMS identity, including lost successful PUTs. Expected
   missing HEAD responses do not suppress later reads; ordinary write batches
   still stop new dispatch after an API failure. Resume reuses verified peers.
   Cluster artifacts and generated installers use groups of at most four with
   controller ownership/cancellation checks between groups. Native hosts publish
   already authenticated running helper bytes into the artifact directory when
   both helper pins match, avoiding a second helper download. Different
   helper pins retain their normal verified fetch. Host commands remain ordered
   under their existing install and command locks.
10. **Volume authorizations share one post-apply checkpoint.** Missing node and
    optional lightwallet-cache authorizations use one operation-scoped Pulumi
    export, with individual EC2 observations and per-target proof/receipt files.
    Saved authorizations validate before missing ones are prepared. Interrupted
    authorization proofs must retain and validate their original checkpoint
    bytes. Checkpoints are not cached across operations.

Transfers, inventory and backend operations share one bounded AWS batching
boundary. Concurrency does not bypass cache verification or Pulumi safety checks.

**The supported deployment topology is one to three nodes.** Larger scheduler
fixtures are not evidence of supported larger deployments, which require
addressing, firewall, capacity and topology qualification. There is no CLI
concurrency flag.

## Recovery and cancellation

Each request keeps its own lock, immutable identity and durable attempt journal.
All supplied journals validate before any batch dispatch. Cached install success
is not dispatched again. Unknown submission replies recover the same attempt;
only a confirmed terminal failure permits an explicit retry. A queued fresh
request gets its execution budget when its slot opens, not while waiting.
Previously dispatched requests already occupy slots on resume.

Failure, deadline, cancellation or progress-reporting errors stop later dispatch.
The controller preserves unfinished submissions as uncertain and makes bounded
best-effort cancellation requests for known IDs; a cancellation request is not
proof of remote termination or rollback. Cancellation persistence failures are
reported, not hidden. Resume through the normal saved-deployment/reconciliation
path; never delete journals or assume that other hosts did not start. Existing
partial-build and partial-provisioning cleanup requirements remain in force.

## Fast iteration with existing commands

- Keep team IAM, build infrastructure and the S3/KMS backend between ordinary
  network tests. Network destruction already preserves these shared resources.
  Fresh-team setup/removal tests must still exercise the full lifecycle.
- Use [selected-node updates](updates.md) for compatible source/image iteration
  rather than destroying hosts, disks and NAT. This is not a database reset or a
  substitute for fresh-install/consensus-change tests.
- Preserve [exact-image reuse and build-layer caches](builds.md). A layer cache
  does not persist arbitrary Docker cache-mount contents. Changed source can
  still require a real build.

For contributor checks and measurement guidance, see the
[test coverage notes](testing.md#subsystem-coverage-notes).

## Source-build transfer and cache limits

Source builds use `docker buildx build --push`. The exporter needs only the
registry manifest and exact raw configuration bytes, not a whole-image archive.
The `zdn-build-export/v1alpha2` protocol retrieves the configuration by its
manifest-bound digest and applies digest, size, platform, provenance, capability
and runtime-default checks. Manifest/config limits are 1 MiB/4 MiB, with bounded
HTTPS downloads and sanitized transport
errors. Metadata export does not eliminate compilation, layer construction,
registry transfer or subsequent host image pulls; the exporter does not verify
layer contents.

The recipe obtains the config blob URL through ECR `GetDownloadUrlForLayer`,
using the existing repository-scoped permission. AWS's own
[ECR containerd resolver](https://github.com/awslabs/amazon-ecr-containerd-resolver/blob/master/ecr/fetcher.go)
uses this API for Docker/OCI config descriptors as well as layers. CodeBuild
Standard 7.0 includes `jq` for extracting the digest.

Optional cache exports use `ignore-error=true`; other Buildx failures do not
trigger a second full `--no-cache` build. This avoids rebuilding on compilation
or push failures without guessing their cause from logs. Missing imports can be
ignored by BuildKit; arbitrary corrupt-cache failures are not guaranteed to
recover. Cache namespaces and verified-result promotion gates still apply.
Only the current exporter protocol is supported. These limits apply to source
builds, not exact-image reuse or prebuilt-image deployments. Performance savings
have not been measured.

Prepared AMIs and shared networking are not supported deployment modes.
Cleanup still requires safe EBS detachment, backend-last deletion and the KMS
waiting period.
