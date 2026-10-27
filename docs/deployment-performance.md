# Faster deployment and cleanup

ZDN overlaps independent node installation, readiness, build transfers, backend
hardening and cleanup inventory. It also avoids repeated inventory and Pulumi
processes. These changes remove controller serialization; they do not promise an
AWS provisioning time or change the private topology.

## Execution plan and implemented boundaries

1. **Keep resource creation dependency-driven.** Pulumi already schedules
   independent resources concurrently. Hosts and disks do not form a per-node
   dependency chain. Keep NAT/private-route readiness before host startup,
   verified images before node allocation, and preview/ownership checks before
   infrastructure effects. Increasing Pulumi parallelism is not this change.
2. **Overlap initial installs and boot preparation.** Prepare exact volume
   authorizations, scripts and uploads while cloud-init proceeds. Poll fresh
   hosts' SSM availability in bounded groups of up to 50 IDs under one separate
   15-minute availability deadline. Admit each online host immediately rather
   than waiting for the last host; offline hosts consume no execution slots or
   command budgets. Recover already submitted commands without an availability
   gate. Optional lightwallet capacity preparation retains its selected-host
   availability requirement before rendering capacity-bound installers.
   A single controller interleaves the existing SSM protocol with up to four
   outstanding remote commands, filling free slots rather than waiting for an
   entire wave. Image pulls, bootstrap and node startup can then overlap across
   hosts. Small AWS submission/status calls remain synchronous; no background
   controller or competing lease writer is introduced.
3. **Overlap fresh node observations.** Use the same scheduler with new per-node
   observation journals. Validate every node's original install identity, active
   image/update, chain readiness and producer contract. Only then may the
   existing producer activation and optional service installation proceed.
   Service actions sharing a host lock and selected-node rolling updates retain
   their existing ordering.
4. **Overlap independent cleanup inventory.** The shared AWS CLI adapter uses a
   rolling pool of at most four calls, retaining input-ordered outcomes and
   joining every local worker before returning, including on failure. Use it for
   the 12 team EC2 inventory families and nine network families. Scan each tagged
   network family once, regardless of node/cache-disk count; reconcile saved IDs
   individually afterward so one missing ID cannot hide another resource. Exact
   observations replace stale tagged identities; a NotFound response never erases
   contradictory tagged evidence. Existing in-process API adapters have a
   sequential default. An API error, malformed/paginated result or remaining
   resource still prevents deletion.
5. **Reduce artifact cleanup round trips.** Network artifact cleanup lists up to
   50 versions/markers per page instead of 10. The CLI projects only truncation
   and exact key/version identities, keeping even long-key responses bounded.
   Normal pages use one deletion request; long escaped identities are split by
   serialized size to stay below the OS per-argument limit. Check partial errors
   after every scoped deletion and relist to prove emptiness.
   No shared state prefix is purged. Team backend purges still acknowledge old
   versions before deleting current versions/markers.
6. **Overlap independent build transfers.** Validate private source/exporter
   copies before either upload. Upload them together and durably record each
   confirmed version on the controller thread, including when its peer fails.
   StartBuild remains downstream of both successful uploads. After the result
   establishes the expected image identity, download manifest/config together
   into separate bounded files; verify bytes before ECR comparison/publication.
   Preserve exact-image reuse and uncertain billed-job recovery.
7. **Batch exact-owned unprotection.** Validate every protected administrator
   resource URN before one variadic `pulumi state unprotect URN...` invocation.
   Never use `--all` or concurrent writers to one Pulumi checkpoint. Uncertainty,
   reconciliation and the fresh absence checks before stack removal are unchanged.
8. **Overlap backend hardening and settings reads.** After verifying bucket ownership
   and region, set public-access blocking and bucket-owner-enforced ACL controls
   together. Require both successes before proceeding to keys or state writes.
   These idempotent operations can resume on the original owned bucket. Keep
   bucket/KMS creation, policy refusal and key/encryption validation ordered;
   never retry an uncertain create blindly. Backend preflight batches its five
   independent S3 settings reads after ownership verification. All five settings
   and the key must still validate before the caller proceeds.
9. **Pipeline immutable artifact delivery.** Verify all staged deployment inputs
   before remote effects. HEAD independent objects together, conditionally PUT
   missing objects together, then reconcile every candidate by checksum, byte
   length, encryption and KMS identity, including lost successful PUTs. Expected
   missing HEAD responses do not suppress later reads; ordinary write batches
   still stop new dispatch after an API failure. Resume reuses verified peers.
   Cluster artifacts and generated installers use groups of at most four with
   controller ownership/cancellation checks between groups. On native hosts,
   publish already authenticated running helper bytes into the artifact directory
   when both helper pins match, avoiding a second helper download. Different
   helper pins retain their normal verified fetch. Host commands remain ordered
   under their existing install and command locks.
10. **Share one post-apply volume checkpoint.** Prepare missing node and optional
    lightwallet-cache authorizations from one operation-scoped Pulumi export.
    Keep individual EC2 observations and original per-target proof/receipt files.
    Validate saved authorizations before preparing missing ones; an all-saved or
    legacy deployment needs no new export. Interrupted proofs must still validate
    and retain their original checkpoint bytes. No backend-wide stale cache is
    introduced.

Transfers, inventory and backend operations share one bounded AWS batching
boundary. There is no cache bypass or increase in Pulumi parallelism.

The node scheduler consumes a collection, not three hard-coded slots. Offline
tests exercise zero, one, three, seven, nine and 53 requests, including slot refill,
availability-query chunking and queued deadlines. **The supported deployment
topology remains one to three nodes**; increasing it still requires addressing,
firewall, capacity and topology qualification. There is no new CLI concurrency flag.

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

## Source builds: direct registry export and bounded metadata

New source builds now use `docker buildx build --push` rather than loading the
image into Docker, pushing separately and serializing every layer again with
`docker save`. Only the registry manifest and exact raw configuration bytes are
needed by the exporter. The new `zdn-build-export/v1alpha2` path retrieves the
configuration by its manifest-bound digest and applies the same digest, size,
platform, provenance, capability and runtime-default checks. Manifest/config
limits remain 1 MiB/4 MiB, with bounded HTTPS downloads and sanitized transport
errors. This removes whole-image work, not compilation, layer construction,
registry transfer or subsequent host image pulls; the exporter does not verify
layer contents.

The recipe obtains the config blob URL through ECR `GetDownloadUrlForLayer`,
using the existing repository-scoped permission. AWS's own
[ECR containerd resolver](https://github.com/awslabs/amazon-ecr-containerd-resolver/blob/master/ecr/fetcher.go)
uses this API for Docker/OCI config descriptors as well as layers. CodeBuild
Standard 7.0 already includes `jq` for extracting the digest. No additional
registry authentication mechanism or service-role permission is introduced.

Optional cache exports use `ignore-error=true`; other Buildx failures no longer
trigger a second full `--no-cache` build. This avoids rebuilding on compilation
or push failures without guessing their cause from logs. Missing imports can be
ignored by BuildKit; arbitrary corrupt-cache failures are not guaranteed to
recover. Cache namespace and verified-result promotion gates remain unchanged.
Only the current exporter protocol is supported; old recipes and archive export
are unsupported. These optimizations apply to source builds, not exact-image
reuse or prebuilt-image deployments. Performance savings have not been measured.

Prepared AMIs and shared networking are not supported deployment modes.
Cleanup still requires safe EBS detachment, backend-last deletion and the KMS
waiting period.
