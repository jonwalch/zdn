# CLI automation

ZDN provides versioned machine results for supported commands. Output selection
does not grant mutation consent, bypass identity checks, or authorize retries.
Keep configuration validity, checked prerequisites, fresh service health, and
wallet/payment qualification separate.

## Agent operating checklist

Use this page to operate the installed product. [AGENTS.md](../AGENTS.md) is
additional guidance for contributors changing the repository, not a prerequisite
for a person connecting to an existing network.

1. **Discover the installed contract.** Read `zdn reference --schema` and the
   relevant long help. Do not invent flags, assume every command supports machine
   output, or treat `--help` as a dry run.
2. **Choose the task.** For a first network, follow [installation](preview-start.md).
   For an existing network, use its original profile, state directory, network
   UUID and receipts. For participant-only access, follow [connections](connections.md)
   rather than creating a second team.
3. **Verify inputs before execution.** Check the selected release's full profile,
   hashes, platform limitations and matching source/notices. Run the applicable
   local checks and offline render. They do not establish AWS authorization,
   network readiness or payment success. Mac browser-download installation is
   [currently blocked](preview.md#platform-and-trust-limits); do not bypass OS trust.
4. **Get consent for effects.** Present the account, region, network, billed
   resources and deletion scope before running cloud or destructive commands.
   `--noninteractive` selects interaction behavior; it is not consent. Do not
   add `--yes` or `--delete-data` unless that exact action is authorized.
5. **Observe and preserve.** Save the terminal result, retry classification,
   operation IDs and receipts in private storage outside captured source. Never
   print credentials, private keys or full wallet backups into logs or chat.
   Use fresh `devnet health` for service readiness, not local `devnet list`.
6. **Recover the same operation.** After a timeout or lost reply, inspect the
   original receipt/journal before another dispatch. Use the documented
   reconciliation path. Resume payments with their original operation UUID and
   identical intent; never create a new payment as a retry.
7. **Close out honestly.** Use [native removal](removal.md), not wildcard AWS
   deletion. Report retained resources, uncertain outcomes and pending checks.
   KMS PendingDeletion is not physical deletion or billing closure. Do not
   promote fixture, offline or health results into live payment qualification.

Live validation, node/container builds, proof generation and performance
workloads need separate scope approval under [contributor test rules](testing.md).
An instruction to review documentation or run ordinary tests is not approval
for those workloads.

## Offline command reference

```sh
zdn --help
zdn wallet --help
zdn help wallet balance
zdn reference
zdn reference --schema
zdn --format json reference --schema
```

`reference` prints every public command's long help, parents before children;
`--schema` emits a standalone JSON document with
`apiVersion: zdn-command-reference/v1alpha1`. Neither command reads configuration,
credentials, wallet state or backends, runs external tools, or contacts a service.
Internal protocols and the generated `help` pseudo-command are excluded. Prefer
`--help` to short `-h` for full descriptions. Help succeeds with exit 0, but it
bypasses required/conflicting argument checks: adding `--help` is not a dry run
and does not establish that the same command without it is valid or safe.

The schema's `commands` array contains each command's `path`, `about`, `longHelp`,
`subcommands`, `subcommandRequired`, `arguments`, and `ancestorOptions`. Arguments
describe names/aliases, position, value cardinality, required/global/repeatable
status, explicit defaults, choices, declared conflicts and explanatory help.
An unbounded `maxValues` is null. `ancestorOptions` records the owning path of
non-global parent options: put root `--format` before the selected command and
wallet `--backend`/`--backend-sha256` before its leaf. Global options work below
their owner; for example `wallet balance --wallet-dir PATH` is valid placement.

The schema deliberately declares `validationComplete: false`. Clap's public
reflection API does not expose every conditional requirement or numeric range.
Read `help`/`longHelp` for conditions, dynamic defaults, trust requirements,
destructive scope and recovery rules; do not treat this document as a complete
validator, execution authorization or qualification claim. Machine wrappers use
the existing result protocol with the schema in `data`; human-format
`reference --schema` emits the schema directly. `reference` rejects progress-file
requests, since discovery is not a lifecycle operation.

## Machine results, errors, and progress

```sh
zdn --format json --noninteractive check
zdn --format jsonl plan
zdn --format json receipt inspect OPERATION_ID --state-dir STATE_DIRECTORY
zdn --format jsonl receipt resume-plan OPERATION_ID --snapshot SNAPSHOT_DIRECTORY
```

Put root `--format human|json|jsonl` before the command. Omission and `human`
preserve command-specific output, often JSON on success and text errors on stderr.
`--output PATH` is an artifact destination, not a format selector.

Machine formats support `reference`, `init`, `check`, `plan`, `receipt inspect`,
`receipt resume-plan`, `foundation up`, `foundation destroy`, `devnet destroy`,
`devnet up`/`up`, `devnet update`, `devnet list`, `devnet status`, `devnet health`,
`doctor`, `package verify`, `package export`, `release sign`, `release verify`,
`release resolve`, `rpc`, and `submit`. Unsupported commands are rejected before
execution. The AWS credential-process protocol, `connect --json`, and
[`exec --events-file`](connections.md) are separate interfaces.

Records use `apiVersion: zdn-cli/v1alpha1` and go to stdout. JSON emits one
terminal record. JSONL flushes `command-started` before execution, optional
observations, then a terminal `result`. Argument failures, help, and version
requests emit only a terminal record; successful help/version records have
types `help`/`version` with text in `data.text`.

| Field | Meaning |
| --- | --- |
| `command` | Selected supported command, or null before selection/for unsupported commands. |
| `type` | `command-started`, `connection-ready`, `saved-phase`, `build-observed`, `update-prepared`, `update-observed`, `ssm-observed`, `operation-started`, `phase-started`, `phase-result`, `result`, `help`, or `version`. |
| `outcome` | `running`, `observed`, `succeeded`, or `failed`; phase results can also be `unknown` or `cancelled`. |
| `networkId`, `operationId` | Known saved identities, otherwise null. RPC/submission/status/health have no lifecycle operation ID. |
| `data` | Command report or sanitized observation; lifecycle failures retain `savedReceipt` or `blockingReceipt` when available. |
| `error` | Null on success; otherwise fixed `code`, `message`, and `retryClassification`. |

Exit status is 0 for success/help/version, 2 for argument errors, and 1 for
command errors/unsupported machine commands. Machine stderr is empty unless
writing the protocol fails. Error records omit argument values, paths, config
contents and raw subprocess output. Success payloads can contain normal paths
and scope information: they are not secret-free exports.

`--noninteractive` suppresses source prompts even on a terminal; machine formats
imply it. It does not imply `--yes` or change lease/reconciliation rules.

## Discovery and verification

`devnet list` reads local records only. `devnet status` reads AWS inventory without
checking live readiness or shared-backend preservation. `devnet health` performs
fresh bounded checks. Completed health reports with `ready: false`, including
denial, timeout or cancellation, retain their full report and exit 1 with
`health-not-ready`.

`doctor` checks local prerequisites, not AWS identity. Machine check details are
fixed `verified` or `unavailable-or-invalid`; incomplete checks retain the report
and return `prerequisites-incomplete`. `package verify` checks bytes and declared
compatibility, not execution, publisher identity or live qualification.

These commands allocate no lifecycle operation ID and reject `--progress-file`.
Failures before a report exists have null data/IDs. Their fixed codes are
`devnet-list-failed`, `devnet-status-failed`, `devnet-health-failed`, `doctor-failed`,
or `package-verification-failed`. Discovery errors are `blocked`, not automatic
retry instructions.

## Implemented lifecycle execution events

Machine lifecycle commands retain normal requirements: `--yes`, verified tools,
AWS access, pinned inputs and reconciliation/lease gates. They can create billed
resources or delete explicitly selected data. See [deployment](private-devnet.md),
[updates](updates.md), and [removal](removal.md).

JSONL lifecycle order is:

1. `command-started`, before preparation, with null IDs.
2. `operation-started`, after saving the operation and deployment's operation ID,
   before lifecycle phases; data is a sanitized receipt report.
3. `phase-started`, after saving Running and before the effect; then `phase-result`
   after saving the outcome. Data contains `phase`, receipt `revision`,
   `stateRevision`, and `cancelRequested`.
4. Terminal `result`, after required lease release has been attempted.

Preparation/staging can fail before an operation exists. Known network identity
is retained, but no synthetic operation/phase events are invented. Observations
are durable transitions, not provider logs, heartbeats, or an exactly-once event
log. A phase result is not overall success.

### Builds, updates, and remote commands

| Observation | Sanitized data and interpretation |
| --- | --- |
| `build-observed` | `attemptId`, `contractSha256`, `sourceUploaded`, `submissionRecorded`, `buildIdKnown`, `reusedFrom`, `jobOutcome`, `imageVerified`. Job outcomes are `succeeded`, `failed`, `fault`, `stopped`, `timed-out`, `unknown`, or null when no terminal result was observed. Job success/reuse does not imply verified image bytes. |
| `update-prepared` | `{updateId: UUID}` after durable preparation or validation of a selected resume UUID. This is not a lifecycle operation ID or evidence of remote work. |
| `update-observed` | `updateId`, `node` (null when finished), `completedNodes`, `finished`, after fresh node checks/durable confirmation and final cluster/service checks. Lease release or later checks can still fail. |
| `ssm-observed` | `attemptId`, one-based `attemptNumber` within its journal, `state`, `commandIdKnown`, `uncertain`, `cancellationRequested`, `failure`. States: `prepared`, `dispatched`, `running`, `succeeded`, `failed`. Failure categories: `request-rejected`, `failed`, `cancelled`, `timed-out`, `invalid-output`, `response-code`. |

Source apply reports build observations before lifecycle allocation, with null
operation ID; source updates already have an operation ID. Terminal `data.build`
retains the latest observation, including pre-allocation failures. Saved initial
build recovery reports its validated attempt before reconciliation/credentials,
with `imageVerified: false` until rechecked. Before lifecycle allocation,
recorded submission without a known terminal outcome is `reconcile-required`;
known build failures and invalid results are `blocked`. Once allocated, the
saved lifecycle receipt controls classification.

Terminal `data.updateId` retains the prepared UUID; `data.update` retains the
latest observation or just the UUID. Confirmed nodes are reobserved without
redispatch, so repeated observations are allowed. A resumed finished intent can
already say `finished: true` while fresh checks are running.

Apply/update emit SSM observations for durable host-command attempts. Cached
successes repeat saved observations without a new remote check. Terminal
`data.ssm` is only the latest observation, not all commands or overall success.
Scripts, outputs, instance/command IDs and diagnostics are excluded. Standalone
health commands do not emit these events. Missing events never permit redispatch.

### Progress files and failures

```sh
zdn --format json --progress-file operation.jsonl devnet up --saved NETWORK --yes
```

For lifecycle commands, root `--progress-file NEW_PATH` creates a private JSONL
file (0600 on macOS/Linux) in an existing directory. Existing files, directories
and final symlinks are not replaced. It receives the flushed event stream even
when JSON stdout contains only the terminal result. JSONL can mirror to both.
This file is an observation channel, not another operation journal or redacted
export. Creation and first write must succeed before preparation. Help/argument
errors do not create it; human mode/non-lifecycle commands reject it.

Fixed errors include `progress-file-failed`, `unsupported-progress-command`, and
`progress-write-failed`. Lifecycle errors use `foundation-up-failed`,
`foundation-destroy-failed`, `devnet-destroy-failed`, `devnet-update-failed`, or
`devnet-up-failed`. Known IDs remain attached. Failures after an observed
operation retain `data.savedReceipt`; uncertainty/reconciliation takes precedence
over cancellation. Refusal due to an earlier unresolved operation retains
`data.blockingReceipt` with `reconcile-required`, null top-level operation ID,
and no new operation/phase events. Errors without observed state are `blocked`.

Progress-write failure stops later effects and still releases any held lease.
Broken streams, partial files and missing terminal results do not establish an
effect's outcome or permit retry. Inspect saved receipts and live state. A crash
can save a transition without delivering its event; reporting adds no automatic
retry, job stopping, rollback, or resubmission.

## Saved-receipt reports and retry classifications

Receipt reports contain saved identities, scope, kind, revisions, cancellation
intent, phase statuses and resume decisions; arbitrary messages, saved results
and external references are omitted. `inspect` has `inputsVerified: false`.
`resume-plan` verifies the original configuration and, for local sources, saved
snapshot/archive hashes without requiring the original checkout. Missing state
is an error, not permission to initialize it.

- `reconcile-required`: saved success, running, unknown or unsafe failure; also
  earlier pending/retry-safe phases when a later phase is non-pending.
- `cancelled`: stopped phases.
- `safe-to-retry`: pending/explicitly retry-safe phases only with verified inputs
  and all later phases pending.
- `blocked`: remaining cases, including unverified inputs.

Overall classification prioritizes unresolved effects, cancellation, blocked
inputs, then safe retries. Later phases have
`requiresEarlierPhaseVerification: true`; guidance does not allow skipping
prerequisites. JSONL receipt success emits `saved-phase` records for one saved
snapshot, not live progress. Reporting success means only that inspection worked.

Every report has `liveStateChecked: false` and `executionAuthorized: false`.
`recovery` gives read-only argument arrays for inspection and, with verified
inputs, resume planning. Paths are absolute; steps have `mutates: false` and
`requiresAuthorization: false`. Reports neither reconcile effects nor verify
current leases/ownership. Existing execution gates remain required.
