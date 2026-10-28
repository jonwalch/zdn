# Operation tracing

Contributor reference for collecting and interpreting private timing records,
not an installation step. For normal use, start with the
[network walkthrough](preview-start.md). Performance workloads require
[explicit scope approval](testing.md#external-system-acceptance); tracing does
not grant permission to run them.

Build with the optional `profiling` feature to record lifecycle timing:

```sh
cargo build --release --locked --features profiling
ZDN_TRACE_FILE=new-timings.jsonl target/release/zdn check
```

`ZDN_TRACE_FILE` must name a new file in an existing directory. On macOS/Linux,
the CLI creates private JSONL output with mode 0600 and never overwrites an
existing file. Initialization failure stops before command dispatch. Stdout and
the [machine-output protocol](automation.md) are unchanged.

## Coverage and privacy

Fixed-name Rust spans cover controller operations such as source capture,
artifacts/builds, state, chain/RPC, wallet history/journals, and lightwallet checks.
Native helper spans cover capacity, storage, verified delivery, installation,
updates, service control, gateway requests, and lightwallet supervision.

Wallet catalog spans distinguish authority validation, SQLite connection setup,
live-record reads, paginated inventory and migration. Settlement spans cover the
explicit format upgrade, canonical-chain reconciliation and archival. These
phases can be expensive independently of the backend wallet; they run locally
on the CLI machine, not on a devnet database service. Per-row validation is not
given an additional span.

Instrumentation omits arguments and return values. The CLI collector includes
only ZDN spans, not dependency events or ordinary log messages; it does not record
wallet contents, RPC payloads, credentials, or raw subprocess diagnostics.

Without the Cargo feature, the spans compile out. Without the environment variable,
the CLI installs no subscriber or trace file. The environment variable is removed
before child processes start, so children do not reopen the controller's file.
A remote helper needs its own profiling-enabled build and explicit configuration.

## Interpret timing correctly

Span-close records contain operation names, nesting, and `time.busy`/`time.idle`.
These are elapsed durations while a span is entered/not entered, not CPU usage.
Nested timings overlap; do not add them as exclusive time. Async spans enter on
polls, and daemon lifetimes close at shutdown rather than installation completion.

Abrupt termination can leave spans without close records. There is no file
rotation or size cap; use bounded diagnostic runs. Tracing has overhead and does
not measure allocations, retained heap, RSS, or a production resource budget.
An embedding library caller may install its own subscriber.

When reporting performance experiments, retain raw samples, source/binary/config
provenance, workload and measurement boundaries, and p50/p95/p99 for every measured
metric and configuration. Keep synthetic controller measurements distinct from
live node performance and compatibility. Such workloads are not part of ordinary
[tests](testing.md).

Use separate absolute Cargo target directories for baseline and changed builds,
and record hashes of the actual executables before sampling. Freeze each version's
source and private-module inputs; do not infer binary identity from a shared
target directory or filename. Finish builds and ordinary tests before collecting
timings, alternate versions within paired samples, and exclude fixture creation
and warmups from reported operation timings.

Peak process RSS is not allocation attribution or process-tree memory and excludes
filesystem page-cache cost. Large accepted payloads, sustained supervision and
external backends need separate studies. Record small-sample p99 as the observed
maximum when using 30 samples, not a stable population-tail estimate. Keep failed
checks and unsuccessful experiments alongside successful results.

## Allocation and retention studies

Compare JSON shapes as well as encoded byte sizes: a record containing many
small values can allocate substantially more than an equally sized string.
Measure exact-ID reads, paginated inventory, full live-record reads, migration
and reorg restoration separately. Include the combined active/quarantine set;
passing the ordinary active-set limit alone does not qualify that path.

Keep allocation traces separate from unprofiled timing and retention trials.
With heaptrack, disable backtrace merging for global-peak attribution, retain
size histograms and time series, and distinguish cumulative allocated bytes from
simultaneously live heap. Verify histogram call counts against the profiler's
summary. Rust v0 symbols may require `c++filt -s rust` after capture. Diagnostic
builds need symbols; their executable sizes are not distribution-size results.

For services, compare the same idle phase early and late, including RSS/PSS,
thread/file-descriptor counts and process-tree observations. Attribute in-process
mock/client allocations separately. Sanitized child environments do not inherit
heaptrack: a parent trace is not whole-process-tree allocation coverage. A low
outstanding heap at exit does not prove that every runtime state is leak-free.

Record failed trials outside successful-run quantiles and keep the stage
incomplete. Preserve private failure fixtures/receipts and non-sensitive phase
diagnostics; a redacted public error plus a deleted temporary fixture may be
insufficient to distinguish a product failure from a fixture failure. Never
convert an interrupted matrix or an unapproved rerun into a qualification pass.

## Distribution size

Release builds strip symbols by default. This removes symbol tables from the
distributed executable without changing panic/unwind policy or enabling LTO.
Keep an unstripped build for symbol-level diagnostics by overriding the setting:

```sh
CARGO_PROFILE_RELEASE_STRIP=none cargo build --release --locked
```

Measure executable bytes and loadable sections separately: symbol-table savings
are download/disk savings, not an equivalent reduction in runtime RSS. Compare
LTO/codegen-unit experiments with both size and representative runtime workloads;
do not assume a smaller executable starts faster. Single build-time/RSS
observations under concurrent compilation do not establish a build-performance
improvement or regression.
