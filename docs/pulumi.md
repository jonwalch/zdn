# Pulumi process adapter

Advanced reference for contributors and operators diagnosing state or interrupted
operations, not an installation procedure. Use the [preview setup guide](preview-start.md)
to install and launch through ZDN. Do not run the adapter's Pulumi commands
manually to bypass ZDN's ownership, lease or recovery checks.

`zdn` renders a Pulumi YAML project and runs the verified managed Pulumi CLI.
The adapter does not download tools, sign in to AWS, choose an account, or break
a remote lock. The operation layer must verify the AWS identity, reserve the
network ID, and hold the operation lease before it calls the adapter.

## Selected state and identity

Every command receives the selected AWS profile and region, an explicit S3
backend, a project name, and a stack name. The backend has the form
`s3://bucket/prefix`. The KMS secrets URL contains the full key ARN, with the
selected account and region. ARN URLs use three slashes, for example:

```text
awskms:///arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab?region=us-east-1
```

Pulumi documents the [KMS URL forms](https://www.pulumi.com/docs/iac/concepts/secrets/#aws-key-management-service-kms)
and [explicit backend selection](https://www.pulumi.com/docs/iac/concepts/state-and-backends/).
The generated project's name and optional backend must match this selection.

The process environment uses an allowlist. It keeps the user's AWS config and
credential file locations for the selected profile. It removes ambient access
keys, session tokens, endpoint overrides, Pulumi credentials, and Pulumi settings.
The selected profile can still use its configured SSO or credential process.
An inherited AWS or Pulumi login cannot select a different state backend.
The adapter does not set `AWS_MAX_ATTEMPTS` or `AWS_RETRY_MODE`. Pulumi's S3
backend and AWS provider use their SDK or selected-profile retry settings.
In particular, zdn does not force a single attempt for a whole apply.
See the [AWS retry settings and precedence](https://docs.aws.amazon.com/sdkref/latest/guide/feature-retry-behavior.html#retry-configuring).

Each generated workspace has its own `.pulumi` directory. This is its
`PULUMI_HOME`. Its plugin directory links to the verified managed installation.
The managed runtime directory is first on `PATH`. Automatic plugin acquisition
and update checks are disabled. `PULUMI_IGNORE_AMBIENT_PLUGINS=true` prevents a
provider on the inherited `PATH` from replacing the managed provider. The
inherited path remains available to credential-process helpers. The CLI executable
uses an absolute managed path.

[Administrator bootstrap](aws-state.md#administrator-bootstrap) uses a separate
protected `zdn-access` stack and administrator S3 prefix. It selects the setup
profile and reuses the saved-plan checks. Normal version 2 foundation commands
use an isolated AWS config with a refreshable role credential process. Both the
S3/KMS clients and the provider receive that config and an empty shared credentials
file, so they cannot fall back to source-profile static credentials. The source
profile name stays consistent across direct AWS and Pulumi operations. Version 1
continues to use the supplied AWS profile directly.

## Stack operations

The client has separate methods for these operations:

| Operation | Result |
| --- | --- |
| List | Read structured results for the selected project and determine whether the stack exists. Reject duplicate, malformed, or foreign project entries. |
| Initialize | Create a new stack with the selected KMS secrets provider. Check the saved stack settings. |
| Select | Select an existing stack and check its encrypted export. A failed selection never initializes a stack. |
| Preview | Save a private update plan and reject deletion, replacement, or removal from state. Do not change AWS resources. |
| Apply | Apply the prepared stack with that saved plan. Require a fresh preview for each attempt. Runtime readiness is a separate check. |
| Outputs | Read version 1 foundation outputs and require the expected account, region, network ID, and resource fields. |
| Refresh | Reconcile state during an explicit retry. This can update state. |
| Destroy preview | Use `destroy --preview-only --json`. Do not remove resources. |
| Destroy | Remove the resources managed by the selected stack. Retention comes from the resource definitions. |
| Remove stack | Remove empty stack state. Do not pass `--force` or remove historical backups. |

Selection accepts deployment export versions 3 and 4 with no extension features.
It checks the exact KMS secrets URL and each resource's project and stack.
Saved AWS providers must use the selected profile, region, account restriction,
and pinned provider version. Selection accepts the pinned provider's checked
defaults: `skipRegionValidation=true` and `skipCredentialsValidation=false`.
Each value can be a boolean or its exact lowercase string form. Omitted defaults
remain valid. Contrary values, malformed values, unsupported provider overrides,
and foreign provider references are rejected, including those in pending operations. A local stack settings file must also use
the selected KMS key.
An empty stack without deployment secrets metadata needs its saved KMS settings
to resume. Removing those local settings before the first update requires recovery.

The CLI flags follow the pinned Pulumi version's
[stack list](https://www.pulumi.com/docs/iac/cli/commands/pulumi_stack_list/),
[preview](https://www.pulumi.com/docs/iac/cli/commands/pulumi_preview/),
[refresh](https://www.pulumi.com/docs/iac/cli/commands/pulumi_refresh/), and
[destroy](https://www.pulumi.com/docs/iac/cli/commands/pulumi_destroy/) commands.
The native preview JSON has no schema version. The adapter checks its shape and
returns a version 1 `zdn` summary. It excludes configuration values, resource
properties, and diagnostic message text from that summary.

Foundation preview uses `--save-plan`. The adapter checks both the preview
summary and each saved plan operation. It permits only create, update, read,
and unchanged resources. A change to host setup that requires replacement stops
at preview. Destructive changes require explicit teardown and a new network.
Apply uses `up --plan` to constrain the update to those operations. Pulumi can
stop after some allowed changes if later resource values disagree with the
plan; a saved plan is not an atomic transaction. See
[Pulumi update plans](https://www.pulumi.com/docs/iac/operations/stack-management/update-plans/).
Pulumi marks the plan file format as experimental. The pinned 3.268.0 flags and
serialization have source and fixture checks. Controlled replacement rejection
also requires live qualification with the pinned tools and provider.

The plan is a mode-0600 temporary file inside the private Pulumi home. The
adapter checks its digest, original file identity, project, and AWS selection
before apply. Each apply attempt consumes and removes the plan, including on
failure. Another preview, stack selection, refresh, or teardown invalidates it.
The CLI writes the unwrapped plan format defined by
[Pulumi v3.268.0 plan serialization](https://github.com/pulumi/pulumi/blob/v3.268.0/pkg/cmd/pulumi/plan/plan.go).
Plan properties and raw plan bytes do not enter receipts.

## Bounds, cancellation, and diagnostics

Commands use argument arrays and closed standard input. They do not run through
a shell. The default time limit is 30 minutes per command. Accepted output is
limited to 8 MiB per stream. The runner checks limits and invokes the lease or
cancellation callback every 100 milliseconds. The operation layer retries
transient renewal failures while its confirmed lease has time remaining. A
returned callback error starts shutdown.

On macOS and Linux, a private `zdn` supervisor creates an OS session before
starting the CLI. The [pinned Pulumi plugins create separate process groups](https://github.com/pulumi/pulumi/blob/v3.268.0/sdk/go/common/util/cmdutil/child_unix.go#L46),
but stay in this session even when their parent exits. Timeout, cancellation,
and callback failure send `SIGINT` to the CLI first and allow up to 30 seconds
for provider completion and checkpointing. Output-limit failures skip that grace.
While the writer waits for cleanup, it continues to check both output streams.
If either limit is exceeded, or its size cannot be checked, it requests forced
cleanup without waiting for the grace period to expire. Diagnostics preserve the
original cancellation, timeout, or lease-check failure; missing cleanup
acknowledgement still takes priority.
The supervisor then stops all remaining groups in its session, including after
normal CLI exit. Session inspection and forced cleanup have a five-second limit.

A short-lived helper joins each target group before sending `SIGKILL`. The OS
refuses groups in another session. The helper's membership keeps the group ID
from being reused until the signal is sent. No cached provider PID is signalled.
The supervisor remains the session leader throughout cleanup and also shuts down
when its private control pipe closes. `/bin/ps` supplies only PIDs and process
states; it does not inspect other processes' arguments or environment.

The private project file `.zdn-pulumi-process.json` records the supervisor session,
CLI PID, run token and cleanup completion. No credentials or arguments are saved.
The supervisor records completion only when no live workload group remains.
Missing completion blocks lease release and another local Pulumi run. If cleanup
is uncertain, inspect the receipt and establish current process ownership before
stopping workers. After all old workers have stopped, archive the incomplete
receipt before retrying. A recorded completion can be reused after a writer crash.
Do not treat a saved PID alone as current ownership.

This contains the pinned CLI and plugins, which use `setpgid`. It is not a sandbox
for a program that deliberately starts another session with `setsid` or changes
its user identity. An interrupted cloud change can still leave pending operations
or a remote lock. Cleanup is not rollback and never clears a Pulumi lock.

Raw output is captured in temporary files and discarded when the command ends.
Private diagnostic receipts keep the operation, result category, exit code,
elapsed time, bounded byte counts, and SHA-256 digests. They contain no raw
output, command arguments, environment values, or secrets. Errors report a fixed
category such as `access-denied`, `aws-session-expired`, or `stack-locked`.
They do not echo provider messages. These receipts locate a failing operation;
they do not replace a deliberate, private cloud diagnostic session.
Lock classification matches known backend lock messages; words such as
`blocked` and `unlocked` do not imply a stack lock. The one automatic teardown
retry is limited to a verified stale NAT address disassociation, with a separate
sanitized proof receipt. See [teardown recovery](foundation-lifecycle.md#teardown-and-data).

For contributor checks, see the [test coverage notes](testing.md#subsystem-coverage-notes).
