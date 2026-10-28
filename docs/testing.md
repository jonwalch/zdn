# Testing

The ordinary suite uses local fixtures, temporary files, subprocesses, and
loopback servers. It invokes no AWS APIs, runs no Docker/node/proof workloads,
and installs no official tool binaries. Production services and test workers
are native Rust; Python is not a test requirement.

## Standard checks

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

Use focused targets while iterating and the full suite before delivery.
For optional tracing builds, also check all features:

```sh
cargo clippy --all-targets --all-features --locked -- -D warnings
```

## Temporary executable fixtures

Keep the ordinary suite parallel. Use
[`tests/support/executable.rs`](../tests/support/executable.rs) to write files
that tests will execute directly, including rewrites of existing fake tools;
keep ordinary data-file writes unchanged. Callers still set the intended modes.
The helper stages bytes as non-executable data, then waits for a local `/bin/cp`
child to write the executable. Only that child holds the executable's writable
descriptor; no retries, sleeps, or production changes are needed.

Writing these executables directly from the multithreaded test harness can race
with another thread's subprocess creation. A child can inherit a writable file
descriptor before its parent closes it and retain it until exec, even with
`O_CLOEXEC`. A concurrent exec of that file then fails with `ETXTBSY` (Linux
errno 26), despite `fs::write` having returned. Closing, chmod, or atomic rename
in the writer thread does not close the child's copy. The child-writer boundary
avoids that inheritance while preserving the fixture's executable path, argv,
signals, and test assertions.

## Native validation (local or CI)

Run these checks on a machine or runner matching the target OS and architecture.
Cross-compilation does not substitute for executing the tests on that platform.

[Native validation](../.github/workflows/native-validation.yml) runs automatically
on pull requests and pushes to `main`, on `ubuntu-24.04` (Linux x86-64),
`ubuntu-24.04-arm` (Linux ARM64), `macos-15-intel` (macOS Intel), and `macos-15`
(macOS ARM64). Each native runner installs the exact `rust-toolchain.toml`
toolchain with rustfmt/Clippy, then runs formatting, the full locked ordinary
suite, strict all-target Clippy, and a locked release build. Jobs have a
45-minute timeout, at most two run concurrently, and one failure does not cancel
the other platforms. Host/compiler architecture checks reject accidental
cross-compilation; only actual successful runner executions establish evidence.

The host-runtime execution fixtures in `tests/host.rs::native_runtime` and
`tests/lightwallet_native_install.rs` run only on Linux x86-64, matching the
deployed host/helper platform. They must not run an ARM controller as an x86-64
helper or weaken the production ELF check.
Portable host manifests, input validation and wrong-architecture rejection
remain covered on the other native platforms.

The lightwallet installation fixture needs GNU `strip` (binutils). It removes
only debug information from a private controller copy before pinning that copy,
so fixture startup does not hash the debug build's full symbol data. The real
supervisor protocol and the startup/cancellation deadlines are unchanged.

On macOS, the generated-build fixture also requires Bash 5 and GNU coreutils
(`brew install bash coreutils`), with `bash` and `sha256sum` or `gsha256sum` on the
test launcher's `PATH`. Bash 5 must precede Apple's `/bin/bash` on that `PATH`:
the fixture selects the first `bash` file. Apple Bash 3.2 rejects the Linux
script's empty arrays under `set -u`. The fixture exposes only the selected shell
and checksum tool inside its isolated tool directory; it does not inherit the
launcher's entire `PATH` or alter the Linux build script. Native CI installs
these prerequisites and puts Homebrew's Bash first on its test `PATH`.

The CI test launcher resolves `TMPDIR` to its physical path before starting
Cargo. macOS temporary paths can have symlinked ancestors, while wallet fixtures
require a non-symlinked root. Explicit symlink-rejection controls still create
their own symlinks beneath that root; production path checks are unchanged.

Logs retain the checked-out commit (the merge commit for pull requests), OS,
architecture, toolchain versions, input/executable hashes, binary format, public
`--version`/`--help`, and the no-cloud runtime capability protocol with supported
and unsupported requirement controls. CI resets SIGINT to its default disposition
before executing `cargo test`, so subprocess cancellation tests do not inherit
an ignored signal. Local launchers that inherit ignored SIGINT must likewise
reset it before executing the suite. This is launch-environment handling, not
a production Python dependency.

The workflow has read-only repository permissions, no cloud credentials, no
cache, no release publishing, and no binary uploads. These tests do not exercise
AWS, live nodes or payments. Keep those results separate as described below.

### Hosted macOS process timeout investigation (2026-10-28)

The [Preview 3 macOS ARM64 job](https://github.com/jonwalch/zdn/actions/runs/40700112519/job/122857306289)
failed in the normal-exit branch of
`memory_capture_kills_inherited_helpers_on_timeout_and_normal_exit`:
`/bin/sh command exceeded its time limit`. The release documentation changes did
not modify this test or `src/dependencies.rs`.

The unchanged focused test subsequently passed **20/20** serial repetitions on
native Apple Silicon macOS 27.0.1, Rust 1.97.1, with physical TMPDIR and default
SIGINT. The dependencies binary also passed **27/27** under default parallelism.
Linux independently passed the same focused 20 repetitions and all 27 dependency
tests. These are not the hosted macOS 15 environment or a new full-suite pass.

Both fixture branches use a 100 ms deadline. It starts after `spawn` returns and
includes subsequent shell execution, child-exit polling, owned-group cleanup
and both pipe EOF observations; a further 10 ms polling iteration may be needed
after cleanup. The hosted failure has no phase trace to distinguish scheduling,
shell execution, cleanup or EOF delay. **The failure was not reproduced and its
cause remains unverified**, not proven flaky or fixed. Runtime/test behavior and
deadlines remain unchanged; no hosted job was manually rerun. If it recurs,
collect phase evidence before changing deadlines or cleanup behavior.

## Focused test map

All commands below run from the repository root. Filesystem/process fixtures
exercise real local boundaries; fake AWS/Pulumi/Docker responses do not establish
those external systems' behavior.

| Area | Focused command | Contract exercised |
| --- | --- | --- |
| Configuration and CLI | `cargo test --locked --test config --test cli` | Strict fields, presets, capability/machine output, input boundaries |
| Source capture | `cargo test --locked --test source_capture` | Working/index/revision bytes, Git isolation, deterministic archives, symlinks, capture races |
| Identities and receipts | `cargo test --locked --test state_store --test operation_receipts` | Scope, concurrent writers, durable phases, cancellation and safe resume decisions |
| Tools | `cargo test --locked --test dependencies` | Version probes, loopback downloads, archive/hash checks and atomic activation |
| AWS and access | `cargo test --locked --test aws --test access --test participant` | Account/profile scoping, generated policies, reservations, leases and grants |
| Resource model | `cargo test --locked --test infra --test cluster_infra` | Private topology, IAM intent, retained disks, capacity and output identities |
| Process supervision | `cargo test --locked --test pulumi --test process_supervision --test host_command` | Cancellation, deadlines, bounded output and descendant cleanup |
| Foundation lifecycle | `cargo test --locked --test foundation --test foundation_cli --test foundation_live` | Intent-before-effects, retries, interrupted teardown and retained data |
| Live adapter logic with fake responses | `cargo test --locked --lib foundation_live` | Lease/SSM timing, uncertain outcomes, volume authorization and cleanup decisions |
| Chain formats | `cargo test --locked --test chain_manifest --test chain_artifacts --test node_config --test runtime_config` | Canonical identity, byte bindings and renderer contracts |
| Bootstrap and production | `cargo test --locked --test chain_bootstrap --test chain_readiness --test chain_producer --test producer_cli` | Saved history/rules, generation intent, lost replies and ownership |
| Native host | `cargo test --locked --test host --test host_volume_prepare --test host_installer_bootstrap --test host_capacity_bootstrap` | Installation identity, storage claims, verified delivery and capacity |
| Native revisions | `cargo test --locked --test host_revision --test host_revision_delivery --test devnet` | Selected images, durable holds, interrupted activation and saved recovery |
| Connections and gateway | `cargo test --locked --test connect_cli --test connections --test endpoints --test client_gateway --test client_gateway_runtime` | Private endpoint identity, RPC policy, HTTP bounds, cookies, tunnels and cleanup |
| Lightwallet data | `cargo test --locked --test lightwallet --test lightwallet_cli` | gRPC framing, bounded streams, compact/tree comparisons and error handling |
| Lightwallet lifecycle | `cargo test --locked --test lightwallet_native_install --test lightwallet_runtime --test lightwallet_cache_prepare --test lightwallet_service` | Native install/daemon/cache contracts, rotation, ownership and cleanup |
| Builds and reuse | `cargo test --locked --test build --test build_infra --test build_export --test build_reuse` | Source contracts, native result export, uncertain-job recovery and verified reuse |
| Packages and releases | `cargo test --locked --test artifact_set --test package --test releases` | Inventories, hashes, parser boundaries and signatures against explicit test keys |
| Discovery and handoff | `cargo test --locked --test devnet_list --test health --test handoff_export --test handoff_import` | Read-only reports, saved inputs, portable state and rejected ambiguous authority |
| Wallet coordination | `cargo test --locked --test wallet_cli` | Hash-pinned fake backend, private files, journals, reservations and immutable signed bytes |
| Removal | `cargo test --locked --test removal --test cluster_cleanup` | Explicit deletion intent, identity rechecks and incomplete cleanup |
| Independent vectors | `cargo test --locked --test reference_vectors` | Fixed encodings/digests reproduced independently of production codecs |

Normal tests never rewrite reference vectors. See the fixture READMEs for
[consensus manifests](../tests/fixtures/chain-manifest/README.md) and
[runtime configuration](../tests/fixtures/runtime-config/README.md) before explicit
regeneration.

## External-system acceptance

Offline success does not establish real IAM enforcement, provider compatibility,
disk formatting/mount safety, node storage migration, peer behavior, valid proofs,
or wallet/lightwallet interoperability. Keep acceptance evidence separate from
fixture results and bind it to exact source, helper/image/configuration hashes,
environment, commands, observed outcomes, and cleanup inventory.

For an authorized acceptance run, cover the relevant public contract:

- Infrastructure: setup identity, denied access, unchanged apply, interruption,
  retained disks, explicit deletion, and independent cleanup observations.
- Builds: exact captured inputs, CodeBuild result, image verification before
  allocation, cache/reuse controls, and artifact/log retention.
- Runtime: installation, bootstrap, scheduled production, restart/cookie rotation,
  interrupted-command recovery, and stable host/volume identities through updates.
- Controller handoff: quiesce the source, transfer checked inputs, establish receiver
  authority, and resume the same work without duplicate dispatch.
- Payments: use the [chain/client acceptance procedure](compatibility.md), including
  funding, receiving, later spending, negative controls, and uncertain broadcast.
- Releases: independently distribute publisher trust and verify actual artifact,
  source, and license provenance; synthetic signatures do not qualify a release.

Record passed, failed, and pending cases separately. Use sanitized reports without
credentials or private wallet data. Live/cloud/build/proof/performance workloads
are separate from ordinary tests and require the explicit approval described in
[repository guidance](../AGENTS.md). Running this test map does not authorize them.

## Subsystem coverage notes

These contributor notes collect the detailed test inventories from the operating
guides. They describe test scope, not the results of a particular release run.
The ordinary checks below use local processes and simulated external responses;
they do not run AWS, Docker, live nodes or proof generation.

### Source builds and reuse

Contract and IAM tests cover upload/start/poll/result failures, cancellation and
deadlines, private receipts, uncertain-start reconciliation, terminal-state
preservation and exact-image reuse with fresh ECR checks. CLI tests cover
failed/corrupt/valid results, lost start replies, interrupted polling, recovery
after working-file edits, changed-config rejection and reuse in another deployment.
Valid CLI output reaches a saved node request; missing managed tools stop the
fixture before provisioning.

Generated shell is syntax-checked. The metadata exporter runs against small
registry/config fixtures. Generated cache scripts run with fake Docker/AWS tools
for cold/warm caches, failed cache/build commands and invalid image results;
only verified successful exports can replace the restored cache. Direct registry
export tests also cover optional cache-export errors, failure before result
publication and transport secrecy.

### AWS identity and infrastructure

Identity tests cover environment conflicts, receipt ordering, partial bootstrap
recovery, foreign-resource rejection, exact AWS JSON/file arguments, competing
conditional reservations, heartbeat races, stale recovery, conditional release
and profile-independent error classification. Both legacy IAM policy creation
orders have regression coverage.

`cargo test --locked --test infra` covers identity, provider selection, private
network paths, role separation, retention, emitted script syntax, output validation
and resource budgets. Readiness tests use synthetic host facts. These tests do
not establish real IAM enforcement, S3/Pulumi lock contention, AWS crash recovery,
provider behavior or billing outcomes. External checks also need installed-tool
compatibility, SSM connectivity, NVMe attachment, reboot readiness, unchanged
updates, both retention choices and independent cleanup observations.

### Block production and host installation

Producer tests use fake clocks, scripted RPC, loopback HTTP, temporary state,
fake systemd tools and fake SSM responses. They cover cadence, slow responses,
durable intents, restarts, late commits, conflicting tips, locks, cancellation,
private cookie authentication, service ordering and activation after all nodes
are ready. External checks must exercise restart, reboot, follower catch-up and
interrupted activation against actual nodes.

`cargo test --locked --test host` uses temporary files and fake executables. It
covers identity/config validation, exact-volume selection, mount mismatches,
unknown signatures and raw data, interrupted/repeated publication, digest checks,
credential redaction, bootstrap ordering, observation without submission and
resource limits. Actual AL2023/EBS/Docker/SSM behavior, controller activation,
bootstrap markers and reboot recovery need external checks.

### Lightwallet service

Local tests cover private/pinned rendering, aggregate budgets, parent cgroup
limits, exact cache identity and mounts, wrong-container refusal, cookie-file
attacks, atomic credential replacement, cookie rotation, cancellation and cleanup
failures. External checks must cover measured-budget enforcement, cookie rotation,
gRPC readiness, cache recovery, host restart and teardown. These local tests do
not establish wallet compatibility, image provenance or useful workload sizing.

### Pulumi and process supervision

`cargo test --locked --test pulumi` uses temporary helper executables. It covers
arguments, environments, stack discovery, account and KMS guards, malformed and
partial output, output versions, cancellation, timeout, descendant cleanup,
output limits and secret-free errors. Provider-state fixtures cover another apply
and teardown, including pending operations. A subprocess fixture checks that an
inherited plugin setting cannot enable ambient providers and that credential
helpers can still run from the inherited path.

Real local child processes check graceful checkpointing after cancellation or
callback failure, forced termination of children ignoring the first signal, and
output overflow on both streams during shutdown after cancellation, timeout or
lease-check failure. `cargo test --locked --test process_supervision` also covers
separate plugin groups, reparented workers, normal CLI exit, loss of the writer
pipe, unrelated processes, foreign/reused group IDs and missing cleanup
acknowledgement. Unconfirmed process cleanup leaves the lease owned.

Saved-plan fixtures cover destructive operations, missing or changed plans,
project changes, one-attempt use, private permissions and exact apply flags.
They need no installed Pulumi CLI or provider. Actual CLI/provider behavior,
S3/KMS state, saved-plan apply, lock contention, pending-state recovery,
replacement rejection and teardown with both retention choices need external tests.

### Concurrent deployment and performance measurements

Offline tests cover overlapping remote commands, arbitrary collection sizes,
result identity/order, slot limits/refill, per-command queue budgets, lost replies,
cached success, failure, timeout, cancellation and observer failure. Cluster tests
retain the all-nodes-ready producer gate and mixed-image validation. Native fake-CLI
processes cover inventory overlap, rolling refill, bounded subprocess counts,
ordered partial successes and complete joining after errors.

Build tests cover either peer's failure/corrupt acknowledgement, private-copy
tampering, reuse of a successful peer and no duplicate uncertain start. Cleanup
tests cover one tagged scan per family across three nodes, individual saved-ID
reconciliation, foreign-URN refusal and lost unprotect replies. Startup tests
prepare installers while SSM is offline without dispatching to unavailable hosts.
Staggered availability installs fast hosts first, while invalid node reports still
prevent producer activation. Existing submissions recover without availability
checks. Artifact tests cover partial-success/resume and immutable-input refusal;
native install tests cover matching/differing helper pins. Backend-hardening
failures stop before key creation and recover without recreating the bucket.

For approved latency experiments, pin source/binary/config hashes and disposable
scope. Compare controllers with identical image, AMI, region, node count and cache
state. Measure setup, build/reuse, Pulumi apply, SSM availability, installation,
final readiness, network destruction and team cleanup separately. Retain raw
observations and p50/p95/p99 per phase/configuration; one successful run is not a
latency distribution. Exercise partial startup/interruption, concurrent bucket
setting failures and exact-owned cleanup through ZDN. See [operation tracing](profiling.md).

### Packages and releases

Package tests use small synthetic archives, OCI JSON and ELF headers to check
consistency and failure handling. Release tests use synthetic keys, small local
fixtures, injected downloads and loopback package tests. They do not establish
reproducible builds, helper behavior, storage compatibility, valid proofs, wallet
compatibility or actual external publishing.
