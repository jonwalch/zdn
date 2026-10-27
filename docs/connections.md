# Private client connections

Use `connect` to test a local application against a running AWS devnet. The
command opens private AWS Session Manager connections and prints local URLs.
New devnet requests include a private client RPC service. Existing requests keep
their saved runtime contract; a legacy request without client access needs a new
devnet binding.

## Connect

Install AWS CLI v2 and an AWS Session Manager plugin newer than 1.2.497.0 for
your operating system and CPU architecture. `connect` checks that the plugin
runs before it contacts AWS. This version requirement keeps session tokens out
of process arguments, using the [AWS CLI's token environment-variable support](https://github.com/aws/aws-cli/blob/v2/awscli/customizations/sessionmanager.py).
Sign in with your AWS profile. A participant does not need Pulumi, Docker, Rust,
or deployment-state access.

```sh
zdn connect my-feature
```

Use `--profile NAME` if the deployment uses a different local zdn profile. Use the
printed HTTP URL for node RPC. Configure a light-wallet client for the printed
gRPC address with TLS disabled on this local connection. Keep `connect` running.
Ctrl-C closes the tunnels and their observed SSM sessions. The devnet keeps
running.

Both listeners bind to `127.0.0.1`. Ports are selected automatically. To request
specific ports, add `--rpc-port 18234 --grpc-port 9067`. An occupied port stops the
command. A disabled light-wallet service is reported explicitly; a requested
`--grpc-port` for that service is an error.

`--json` prints one readiness record after all selected tunnels and service
checks pass. Node RPC must report the expected network and chain identity. When
gRPC is enabled, its latest block must agree with node RPC. A tunnel failure
closes the other tunnel and returns an error. The command does not reconnect or
retry transaction submission.

Connection readiness does not establish wallet compatibility or prove Ironwood
payments.

### Secret-safe tunnel failure diagnostics

Observed process/output failures and listener-startup timeouts include
`SSM tunnel diagnostics:` in the returned human-readable error (and therefore
human CLI stderr). Process/output failures
include one JSON object; a startup timeout includes an array for the selected
tunnels. This is diagnostic context, not a new machine-event or receipt schema.

- `category` is a fixed observation: `process-exited`, `output-rejected`,
  `supervisor-unconfirmed`, or `startup-timeout`. It is not a root-cause diagnosis.
- `service` is `rpc` or `grpc`. `listenerState` is `before-listener` or
  `listener-observed`; `sessionNoticeObserved` records only whether a session
  announcement was parsed, not its ID. A listener notice does not prove service
  identity, channel health or wallet readiness.
- `exitCode` and `signal` preserve the supervised AWS CLI's observed completion,
  including exit zero. They are null when unavailable, not guessed from output
  or from the later cleanup-induced exit. They are not necessarily the plugin's
  own exit status: AWS CLI may translate or hide that result.
- Each of `stdout` and `stderr` reports only `observedBytes`, a saturating byte
  count. Empty output has a zero count. These describe bytes drained before the
  diagnostic snapshot, not a guarantee of complete stream capture.

No raw output snippets, session IDs, target identifiers, URLs, argv or environment
values are added to this diagnostic. No output hashes or message-derived
categories are retained, and no persistent raw-output log is created. Existing
cleanup receipts and remote-termination handling remain unchanged; failures still
clean up owned sessions without retrying or reconnecting. The diagnostic survives
successful cleanup in the returned error even though temporary supervisor
receipts are removed. Retaining counts and lifecycle observations helps compare
failures; it does not establish why a session ended.

## Run a command with scoped connections

```sh
zdn exec my-feature -- ./my-integration-test --case private-network
zdn exec --endpoints endpoints.json --aws-profile devnet-participant -- python3 test.py
```

`exec` accepts the same network/profile selection, endpoint file, local ports and
startup timeout as `connect`. It verifies AWS identity, fixed session documents,
all tunnel listeners, node identity and (when enabled) gRPC's observed chain
before starting the program. It does not retry the program or reconnect tunnels.
The command after `--` is an argument vector; no shell is implied.

The child receives these environment variables:

| Variable | Value |
| --- | --- |
| `ZDN_RPC_URL` | Verified loopback node RPC HTTP URL, without a cookie. |
| `ZDN_LIGHTWALLET_GRPC_URL` | Loopback gRPC HTTP URL (TLS disabled); absent when lightwallet is disabled, even if inherited from the caller. |
| `ZDN_NETWORK_ID` | Selected network UUID. |
| `ZDN_CONSENSUS_FINGERPRINT` | Selected chain fingerprint. |

The working directory and original environment are preserved, except these four
variables are replaced with the selected connection values. The temporary AWS
credential bridge used for tunnel ownership is not injected into the child.
Caller-supplied credentials remain caller-supplied; this is not a sandbox for
untrusted code. The node cookie is never exported.

This initial interface is noninteractive: stdin is closed, stdout/stderr pass
through unchanged, and no readiness JSON or machine events are mixed into child
output. Root `--format json` and `--format jsonl` reject `exec` before effects;
use the separate `--events-file` channel below. A child has a maximum 24-hour runtime.

When the child finishes, the CLI stops its remaining supervised descendants and
closes the tunnels. Cancellation or a tunnel failure also stops the child and
cleans up local processes and observed remote sessions. On macOS/Linux, the exit
contract is:

- Preserve the child's exit code when all cleanup succeeds; a child killed by
  signal N maps to 128 + N.
- Return 130 for CLI cancellation after successful cleanup.
- Return 125 for preflight, startup, tunnel, deadline or cleanup failure. If the
  child's status is known, keep it in the stderr failure diagnostic. Cleanup
  failure overrides even a successful child, and retains the private receipt
  directory for inspection.
- Invalid CLI arguments still return 2. A child may itself return 125 or 130;
  infrastructure/cancellation failures are distinguished by a `zdn:` diagnostic.

### Separate exec event file

```sh
zdn exec my-feature --events-file run.jsonl -- ./my-integration-test
```

The opt-in file uses the `zdn-cli/v1alpha1` envelope, independently of child
stdout/stderr. It is created with private mode 0600 (subject to umask) before
preparation; an existing file, directory or symlink is never replaced. Its parent
directory must already exist. No event path is injected into the child.

Each record is flushed: `command-started` precedes preparation,
`connection-ready` follows verified service identity, `child-started` follows a
token-checked supervisor receipt confirming the workload (not just the helper)
launched, and `result` follows cleanup. `networkId` is retained after preflight;
`operationId` is always null. These are observations, not a durable job journal.
A missing `child-started` or terminal record does **not** establish that the
program never ran. A crash or write failure can leave a truncated final line.

Terminal `data` contains the command `exitCode`, nullable `childStatus` with
`exitCode` and `signal`, independent `cancelled`, `tunnelFailed` and `eventsFailed`
flags, and `cleanup` (`no-sessions`, `complete`, or `incomplete`). Unknown child
status fields remain null; known results survive infrastructure failures.
Nonzero results use fixed `exec-failed` errors: known child results or incomplete
cleanup are `reconcile-required`, other failures `blocked`. No automatic retry is
offered. Records exclude argv, environment, child output and arbitrary diagnostics.

A failed initial write prevents preparation. A failed readiness write prevents
launch and still cleans up sessions. Reporting failure after launch still stops
owned processes and cleans up connections. A failed terminal write returns 125,
keeps known child status in stderr and never replays the program; it cannot undo
child effects. Do not infer retry safety from an incomplete file. File creation
and writing failures also return 125. Without `--events-file`, existing behavior
is unchanged. This does not enable root machine formats for `exec`.

Containment uses the existing POSIX session supervisor, not saved numeric PID
signalling. Programs that deliberately escape the session are outside its
guarantees. If AWS creates a remote session but its ID is never observed locally,
the CLI cannot identify or explicitly terminate it; the same limitation as
`connect` remains.

## Make a one-shot read-only RPC request

```sh
zdn rpc my-feature getblockcount
zdn rpc my-feature getblockhash --params '[17]'
zdn rpc --endpoints endpoints.json --aws-profile devnet-participant getblockchaininfo
```

`rpc` uses the same network/profile selection, endpoint files, ports and startup
timeout as `connect`. It verifies AWS identity, fixed session documents and all
selected services (including optional lightwallet chain agreement) before sending
one request to the private node RPC gateway. It never exports the node cookie.

Only an explicit read-only subset of the gateway methods is available: chain,
block, mempool, transaction and address queries, including `getblockcount`,
`getblockhash`, `getblock`, `getblockchaininfo`, `getrawtransaction` and
`getaddressbalance`. Administrative/mining calls and `sendrawtransaction` are
rejected locally, before AWS preflight. Use the separate `submit` command for
transaction submission.
`--params` defaults to `[]` and supplies method parameters as a JSON array or
object, not the request envelope. Batches are not supported. Method and params
validation happens before AWS.

By default, the CLI checks the response envelope and exact request ID, then closes
local connections and terminates observed remote sessions **before** printing the JSON
result alone to stdout. A null result is printed as `null`. Exit 0 means both the
request and cleanup succeeded. Request, identity, cancellation, deadline and
cleanup failures return 1 with a stderr diagnostic and no result on stdout;
invalid CLI syntax returns 2. Node error diagnostics include the numeric code,
not arbitrary upstream error text. Cleanup failure overrides a successful reply.

The RPC exchange has a 10-second deadline and 8 MiB request/response limits,
separate from connection readiness timeouts. Proxy environment variables and
HTTP redirects are not used. No request is retried and no tunnel reconnect is
attempted. Cancellation during a synchronous identity check or RPC exchange is
handled when that bounded request returns or times out, then cleanup runs. Root
`--format json` and `--format jsonl` provide the
[machine contract](#machine-results-for-rpc-and-submit) instead of raw results.
The unknown remote-session-ID cleanup limit
described above still applies.

## Submit an already-signed transaction once

```sh
zdn submit my-feature --transaction-file signed-tx.hex
zdn submit --endpoints endpoints.json --aws-profile devnet-participant --transaction-file signed-tx.hex
```

This command broadcasts a transaction; it does not construct, fund, sign or
qualify it. The regular input file must contain nonempty, even-length hexadecimal
text, with optional surrounding ASCII whitespace. File and serialized request
limits are 8 MiB. Input validation precedes AWS calls. Network/profile selection,
identity checks and optional lightwallet chain agreement are the same as `rpc`.
The CLI sends at most one `sendrawtransaction` request to the private gateway,
with a 10-second deadline, no proxies, redirects, reconnect or automatic retry.

By default, unlike read-only RPC, stdout is a `zdn-submission/v1alpha1` report even
on runtime failure. Its `outcome` is independent of `cleanup`:

| Outcome | Meaning |
| --- | --- |
| `not-dispatched` | The CLI did not attempt submission, or the versioned gateway explicitly confirms no upstream application-request write could have begun. |
| `node-rejected` | A validated node error reply was received; `code` is numeric. This does **not** prove the transaction was never accepted earlier. |
| `acknowledged` | A valid 64-hex `txid` was returned. This is **not** confirmation, finality or payment qualification. |
| `outcome-unknown` | Submission was attempted but a trustworthy result was not received. The transaction may have been accepted. |

Gateway-generated error `data` contains only `apiVersion` and `outcome`; upstream
error text/data are not forwarded. Before the first possible upstream request
write, gateway failures return HTTP 502 with `not-dispatched`. Lost replies,
invalid txids and protocol failures after that boundary return `outcome-unknown`.
Node rejection returns HTTP 200 with `node-rejected`. Older gateways without this
metadata can still return acknowledgements and node rejections, but their generic
HTTP failures are conservatively unknown, never proof of non-dispatch.

Reports contain `transactionSha256` after valid input has been decoded: the SHA256
of the raw transaction bytes, **not the Zcash txid**. They include the selected
`networkId` and `consensusFingerprint` after preflight, and an optional human
`diagnostic`. Raw transaction bytes, node cookies and upstream error messages are
not included. `cleanup` is `no-sessions` before connection startup, `complete`
after confirmed local/observed-session cleanup, or `incomplete`. The existing
unknown remote-session-ID limitation still applies.

Exit 0 requires acknowledgement, successful connection lifecycle and complete
cleanup. All other runtime outcomes return 1; invalid CLI syntax returns 2.
Cancellation or failed cleanup **never erase** a known acknowledgement/rejection;
inspect the report rather than treating a nonzero exit as permission to retry.
Cancellation during the bounded RPC exchange is handled after its reply or
deadline. Root machine formats wrap the retained submission report as described
below; they do not change dispatch, cleanup or retry behavior.

There is no durable submission journal or cross-invocation deduplication yet.
Repeating the command sends again. If the process dies, output is lost, or an
outcome is unknown, reconcile against the intended chain before deciding what
to do; never blindly resubmit.

## Machine results for RPC and submit

```sh
zdn --format json rpc my-feature getblockcount
zdn --format jsonl submit my-feature --transaction-file signed-tx.hex
```

Both commands support the existing `zdn-cli/v1alpha1` envelope. `json` emits only
one terminal `result`. `jsonl` flushes `command-started` before preparation, then
`connection-ready` after all selected service identities have been verified and
before sending the requested RPC, then the terminal result after cleanup is attempted.
Failures before readiness omit `connection-ready`. The observation has
`outcome: observed` and data containing the chain fingerprint, service names and
`paymentQualified: false`, not credentials or local ports. Readiness is neither a
durable lifecycle transition nor a guarantee of continued service health.

Execution records have `command: rpc` or `submit`. `networkId` is retained after
successful preflight, including on later failures; it is null before then.
`operationId` is always null: these commands allocate no durable operation receipt.
Exit codes remain 0 for command success, 1 for runtime failure and 2 for invalid
CLI syntax. Argument/help/version records use the existing root contract.

For RPC, a successful terminal record has `data.result`, including an explicit
null for a null node result. Errors use fixed code `rpc-failed`, classification
`blocked` and null data; successful read results are discarded if cancellation
or cleanup fails. RPC success data is the node result, not a redacted export.

For submission, **both successful and failed** terminal records have
`data.submission`: the `zdn-submission/v1alpha1` report without its human diagnostic.
The outer `outcome` describes the command, not transaction acceptance. Thus a
failed command can retain `data.submission.outcome: acknowledged` and its txid.
Failures use fixed code `submission-failed`. Unknown outcomes, retained
acknowledgements on command failure, and incomplete cleanup are
`reconcile-required`; all other failures are `blocked`. None authorize a retry.
Raw transaction text, input paths, arbitrary diagnostics and upstream error
messages are not exported. Stderr is empty unless writing the protocol fails.

A failed JSONL start write prevents AWS preparation; a failed readiness write
prevents the requested RPC and still triggers cleanup. Cancellation is checked
again after that write. A failed **terminal** write cannot undo a request already
sent. JSON has no progress write before dispatch. A broken/missing terminal record
therefore establishes no submission outcome, and neither format adds a durable
journal or cross-invocation deduplication. Reconcile before considering a resend.
`exec` still rejects root machine formats to keep events out of child output.

## Share a devnet

The operator exports a new file after client-service installation completes:

```sh
zdn endpoints my-feature --output endpoints.json
```

The file contains network, chain, account, region, and service-target identities.
It contains no credentials, cookie, state-bucket location, local AWS profile, or
local port. Export reads saved state; it does not grant access or perform a fresh
service check. Existing output files are never replaced.

A participant uses their own AWS profile:

```sh
zdn connect --endpoints endpoints.json --aws-profile devnet-participant
```

This path does not open the operator's local state or read S3/Pulumi state. The
AWS profile must authenticate to the file's account and have access to its fixed
SSM documents and instances. The CLI checks the default document contents before
starting a session. A document cannot select another remote host or port.

Relative `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CA_BUNDLE`, and
`PATH` entries are resolved from the directory where you start `connect`.
Preflight and the tunnel subprocesses use the same locations.

## Grant participant access

An administrator can use the tool to create a separate role for one network.
Use a team definition owned by the operator, the exported endpoint file, and the
participant's exact IAM user or role ARN. Roles for the zdn host, deployment, and
other participants cannot be selected as trusted callers.

```sh
zdn setup participant \
  --from team.yaml --endpoints endpoints.json \
  --aws-profile administrator \
  --trust-principal arn:aws:iam::123456789012:user/developer \
  --plan
```

Replace `--plan` with `--yes` to apply. This administrator command needs the
managed Pulumi tools and access to the shared state backend. It creates a
protected participant role in a separate administrator stack. It does not change
the deployment role or export temporary credentials.

Setup prints `roleSessionNames`, a map from each trusted principal ARN to its
required session name. Configure the participant's AWS profile to assume the
printed role ARN from their own signed-in source profile. Copy the session name
for that source principal. In the AWS config file, for example:

```ini
[profile devnet-participant]
region = us-east-1
role_arn = PRINTED-PARTICIPANT-ROLE-ARN
source_profile = YOUR-SIGNED-IN-PROFILE
role_session_name = PRINTED-SESSION-NAME-FOR-YOUR-PRINCIPAL
```

The trust policy enforces a different name for each trusted IAM user or role
with [`sts:RoleSessionName`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#ck_rolesessionname).
A caller cannot select another trusted principal's name. A shared source IAM
role counts as one participant: people using that same role share its session
ownership. Use distinct source principals when their sessions must be isolated.
Setup rejects a trust policy larger than [IAM's default 2,048-character limit](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html)
before creating resources; select fewer principals if that limit is reached.
The role permits only the network's client
connections and termination of the caller's own sessions. It grants no shell,
Run Command, deployment, S3-state, KMS, or IAM access. Additional policies must
not be attached to this role; repeat setup verifies its exact trust and policy.

Repeat setup with the same inputs to verify or finish the grant. After an
uncertain apply, inspect the saved receipt and use `--reconcile`. A different
network, target, or trusted-principal set cannot be substituted during recovery.
For a grant created before enforced session names, repeat the original setup
command with `--yes`, then update each participant profile from `roleSessionNames`.
Setup preserves the original project and receipt, validates the owned checkpoint,
and applies the stricter trust policy using `project-v2`. Only the exact old
policy for the same principals is accepted as an upgrade input. Final verification
requires the new conditions. A trust update does not revoke existing STS credentials
or close old tunnels: terminate old sessions and revoke or let old credentials
expire before relying on the new isolation boundary.
[Participant removal](removal.md#remove-a-separate-participant-grant) now removes
the separately owned grant using its original receipt. It refuses active sessions
instead of terminating them, and reports a narrowly scoped live denial check
separately from IAM absence. Network teardown deletes its session documents and
hosts, so the protected administrator role cannot connect to those removed
targets. That role remains until explicit [team removal](removal.md#remove-an-originally-created-team).

Operators with an existing managed deployment role must repeat their original
`setup bootstrap` command to install the new scoped session permissions before
launching a new client-enabled devnet.

## Service boundary

Node RPC is exposed through a private loopback proxy on port 18234. It permits
an explicit set of chain queries and `sendrawtransaction`. It refuses mining,
block-template, administrative and wallet-management methods, batches,
notifications, unsupported HTTP paths, and oversized requests. The proxy reads
the current private node cookie for each upstream request; clients never receive
that cookie. The node's administrative RPC remains separate.

lightwalletd stays on its private loopback port 9067. Fixed-port session documents
are named with both the team's bootstrap UUID and the network UUID. Their only
caller parameter is a local port. Documents and the gateway are managed with the
devnet; the participant IAM grant is managed by the administrator.

The proxy installs separately from the node runtime. Installation verifies the
saved host and disk identity, exact scripts and unit files, and authenticated
node readiness. Recovery settles an in-flight installation before observation.
Only an exact stopped-service observation can authorize one restart attempt.
Changed or foreign files are never silently replaced.

The CLI supervises the AWS CLI and its plugin children. It discards bounded
process output and explicitly terminates every observed session ID. If the CLI
is killed or a StartSession response is lost before any session ID is observed,
it cannot confirm remote termination for that unknown session. Inspect AWS
Session Manager in that case; this version does not claim a bounded remote
orphan lifetime.

AWS references: [port forwarding](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html#sessions-remote-port-forwarding),
[session document schema](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-schema.html),
and [session ownership restrictions](https://docs.aws.amazon.com/systems-manager/latest/userguide/getting-started-restrict-access-examples.html#restrict-access-example-user-sessions).
