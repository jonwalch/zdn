# AWS identity and team state

Use this page to set up account access, share a team export or recover an
interrupted setup. Start with [one-time account access](#one-time-account-access);
for a complete first network, follow the [installation walkthrough](preview-start.md).
Setup changes IAM and storage in the selected AWS account and can incur charges.

The cloud foundation uses AWS CLI v2 **2.37.4 or later**, a named AWS profile, an
expected account ID, and one deployment region. The live adapter checks the CLI
version before it makes an AWS API request. A local fixture executable can test
the process contract without AWS credentials or a network connection.

The selected profile supplies credentials through the normal AWS profile chain,
including SSO and an assumed role. `zdn` checks STS before setup or a foundation
operation. A wrong account or expired session stops the operation. An expired
session shows the `aws sso login --profile ...` command. Environment credentials,
web-identity or container credentials, conflicting profile/region values, and
endpoint overrides are rejected. The child receives the selected profile and
region; it ignores configured endpoint overrides. The tool never writes AWS
credentials into a team file or operation receipt.

The AWS child process selects JSON for successful output and pins
`--cli-error-format legacy` for errors. This flag overrides profile error-format
settings and is supported by the minimum CLI version. The error parser keeps
only a bounded API error code; it does not copy AWS error messages into receipts
or diagnostics. Missing resources and conditional-write conflicts therefore keep
the same meaning when a developer uses JSON, YAML, text, or table errors in their
own shell. [AWS error formats](https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-error-format.html),
[AWS CLI 2.37.4 options](https://github.com/aws/aws-cli/blob/2.37.4/awscli/data/cli.json).

AWS IAM grants access. A team file records that access context; it does not grant
permission. Use a separate AWS account, backend, key, and local profile for an
organization that must not share access. The current implementation supports the
commercial AWS partition.

## Team definitions

A strict, versioned team definition records:

- The team ID, revision, and backend bootstrap ID.
- The expected AWS account and region.
- A private S3 backend URL and the full immutable KMS key ARN.
- In `zdn-team/v1alpha2`, the deployment role ARN, ownership, and runtime boundary ARN.

The local profile adds that developer's AWS profile name. No profile name or
credential needs to be shared with other developers. Import validates the
existing backend without changing its policy, encryption, or ownership. Unknown
fields, a key in another account or region, and a state prefix that overlaps
`zdn-meta` fail validation. Version 2 also reserves `zdn-admin` for administrator state. Setup imports an existing `zdn` team definition;
arbitrary unmarked buckets and keys are not silently adopted.

A team backend looks like `s3://example-state-bucket/pulumi/team-a`. Deployment
metadata uses `zdn-meta/v1/team-a/` in that bucket, outside the Pulumi prefix.
Pulumi secrets use an explicit URL such as
`awskms:///arn:aws:kms:us-east-1:123456789012:key/KEY-ID?region=us-east-1`.
The key ID in a real team file is a UUID. The three slashes are required for a
full ARN. [Pulumi KMS secrets documentation](https://www.pulumi.com/docs/iac/concepts/secrets/#aws-key-management-service-kms).

## Setup and recovery

Backend setup runs before a Pulumi stack exists. It uses direct AWS APIs and
writes a local recovery receipt before its first mutation. The receipt includes
the account, region, exact bucket/prefix, bootstrap ID, creation attempts, known
key ARN, and completion state. Writes are atomic and flushed. A file lock stops
two local setup processes from changing the same receipt.

Setup creates the bucket with ownership tags in its creation request. A lost
successful response can be recovered from those tags. It checks account,
region, and tags before reusing a bucket. It does not tag an unmarked existing
bucket to claim it. The current AWS API supports tags on creation for a general
purpose bucket; the setup role needs `s3:TagResource` for this request.
[AWS CreateBucketConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucketConfiguration.html).

Setup configures all four S3 public-access blocks, disables ACLs, enables
versioning and KMS object encryption, and installs a policy that denies insecure
transport. It enables rotation on its symmetric customer KMS key. Existing
unrelated bucket policies or KMS encryption settings stop setup; they are not
overwritten. The account-root default KMS policy delegates authorization to that
account's IAM policies. There is no default cross-account grant.

S3 object encryption and Pulumi secret encryption protect different layers.
Both select the recorded key. Setup does not store node or wallet secrets.

The direct AWS CLI adapter makes one API attempt per call. Pulumi's provider and
S3 backend retain their SDK or selected-profile retry settings. Conditional
metadata conflicts have bounded retries. A mutation with an uncertain result is not blindly
repeated. In particular, KMS key creation has no idempotency token. If its
response is lost, preserve the receipt, inspect keys with its bootstrap ID, and
supply the matching key ARN by repeating the original `zdn setup bootstrap`
command with `--recovered-key ARN`, keeping its original profile, state directory
and setup inputs. Do not edit the receipt to insert the key. Recovery
checks the key's account, region, type, state, and ownership tags. It does not
create a second key to conceal the interrupted request. If a bucket creation
attempt has no observable bucket, preserve the receipt and inspect the AWS
result before manual recovery. Completed, originally created teams can use the
separate [guarded team-removal workflow](removal.md#remove-an-originally-created-team).

## Reservations and deployment leases

A network reservation binds a full network UUID to its team/account/region and a
creation-owner UUID. A conditional `If-None-Match: *` write creates it. Retrying
the identical reservation succeeds; another owner or scope fails. Deleting a
network does not make that UUID available for reuse.

A deployment lease records the reservation, operation UUID, process-holder UUID,
expiration, and a monotonically increasing generation. Acquisition, heartbeat,
release, and recovery use S3 conditional writes. S3 `If-Match` compares the exact
observed ETag. Conflict errors stop mutation; retries do not invent a new owner.
[AWS conditional PutObject requests](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-object.html).

During an active operation, transient renewal errors use bounded backoff while
the confirmed lease has sufficient time left. Retries preserve the attempted
record. An exact readback can recover a successful renewal whose reply was lost;
a different owner or record stops work. See the [renewal and shutdown bounds](foundation-lifecycle.md#saved-state-and-concurrency).
Acquisition also recovers a lost success reply within the same CLI attempt. It
uses at most three conditional writes, retaining the original holder, expiry,
generation and condition, and accepts only an exact readback. If those checks
fail or the process exits, the next CLI attempt has a new holder: inspect the
unresolved lease and use explicit expired-lease recovery when appropriate.

The lease-renewal loop, specific conditional-write paths, and final IAM setup
verification retry selected direct AWS CLI errors. This is not a general retry
policy for every CLI call. Known transport and transient service errors can be
retried. Recognized expired login/SSO, missing credentials and configuration
errors stop immediately with sanitized categories. An unknown `CommandFailed`
also stops; it is not assumed transient. Raw CLI diagnostics remain private.

Release writes a conditional tombstone. It never deletes the lease object. An
old holder cannot delete or overwrite a newer lease after a heartbeat or
recovery. An expired lease requires explicit recovery with its observed ETag;
there is no automatic takeover or blind force-unlock. Before recovery, stop the
old operation and inspect its receipt and Pulumi lock. Keep operator clocks
synchronized. The lease protects the complete operation; Pulumi's own lock also
protects its state updates. Neither lock proves that a remote process has
stopped.

## Permission boundaries and remaining evidence

The setup administrator needs S3 backend creation, tagging, guardrail and policy
configuration, and KMS creation/rotation/read access. Normal deployment identities
need state/metadata object access, bucket inspection, KMS encryption/decryption,
and the scoped EC2/IAM/SSM actions for the foundation. Participant identities
need only the permitted service/session actions. Runtime instance roles have SSM access. The node extension adds read-only access
to the team artifact prefix, artifact KMS decryption through regional S3, and
ECR pulls from the team namespace. They have **no Pulumi state, lease, reservation,
or IAM permissions**.
Administrator role setup below renders these deployment permissions. Legacy
backend-only setup still needs an externally provisioned operator identity.
The generated policies cover the health-test foundation and private node
deployment. [Build permissions](builds.md#2-administrator-resources) and
[participant access](connections.md#grant-participant-access) have separate
scoped contracts. No public gateway is provided.

Normal foundation teardown preserves the shared state bucket, KMS key, team
settings, network reservation, and operation history. These may continue to
incur storage or KMS charges. Shared-backend deletion needs a separate
administrator process after checking every network and state reference.

## Administrator bootstrap

### One-time account access

For the lowest-friction individual setup in a **dedicated development account**,
have an existing account administrator grant your non-root source identity the
AWS-managed [`AdministratorAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.html)
policy (`arn:aws:iam::aws:policy/AdministratorAccess`). It grants `Action: *` on
`Resource: *`: this is broad account administration, **not a least-privilege
ZDN-only policy**. It covers backend/IAM setup, deployment-role assumption and
final team cleanup. ZDN does not grant these permissions to its own caller.

If your organization uses IAM Identity Center, ask its administrator for an
approved administrator-capable permission set in the development account and use
your existing SSO profile. Do not create another IAM user or access keys just for
ZDN. In a shared/production account, have the administrator review the required
setup/removal permissions instead of blindly granting account-wide administration.
Organization policies, permissions boundaries and explicit denies still apply;
attaching `AdministratorAccess` does not override them.

For an **existing IAM user**, the console path is **IAM → Users → YOUR-USER →
Permissions → Add permissions → Attach policies directly → AdministratorAccess**.
Alternatively, the existing administrator can run this one-time grant, replacing
both placeholders (this changes IAM permissions):

```sh
aws iam attach-user-policy --profile EXISTING-ADMIN \
  --user-name YOUR-USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

For browser-based `aws login`, the narrow AWS-managed
[`SignInLocalDevelopmentAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SignInLocalDevelopmentAccess.html)
policy grants the sign-in actions. Keep it if already attached;
`AdministratorAccess` already includes those actions, so a second policy or
second authenticated identity is not required. Authenticate your non-root user
using MFA, without creating long-lived access keys:

```sh
aws login --profile zcash-admin
aws sts get-caller-identity --profile zcash-admin
```

For an existing Identity Center profile use `aws sso login --profile zcash-admin`
instead. Confirm the expected account and non-root identity; STS success proves
identity, not effective authorization for every setup action. For IAM users,
use the returned IAM ARN as `--trust-principal`; for SSO use the exact IAM role
ARN supplied by the administrator, **not** the returned STS session ARN.
Then use the [single-profile bootstrap command](../README.md#set-up-aws-access).

### ZDN role setup

Enable role setup with one or more `--trust-principal` arguments. By default,
`--aws-profile` supplies both administrator setup credentials and the source
credentials for assuming the deployment role. The recommended individual flow
uses one authenticated, administrator-capable non-root IAM user or Identity
Center role, trusts that exact IAM principal, and reuses the login for final
team cleanup. It does not need another human sign-in or another AWS account.
Use `--developer-aws-profile` only to select a different source identity for
deliberate administrator/developer separation; explicitly repeating the same
profile is also accepted. Omitting both role options retains legacy backend-only
setup, not automatic role creation.

Before creating backend resources, setup verifies that the selected deployment
source is one of the exact trusted IAM principals. An assumed-role source needs
read-only `iam:GetRole` for its own role: ZDN resolves the real IAM path and
checks the role ID against the STS session identity instead of constructing an
ARN from the session's role name. A mismatch or unavailable lookup refuses
before backend creation. In the split-profile flow, the administrator need not
be a trusted deployment source; the explicitly selected source must match.

See the [setup command](../README.md#set-up-aws-access). The administrator profile
must already have backend and IAM setup/removal permissions and permission to
assume the created role. Pulumi cannot grant missing permissions to its caller.
Source login expiry still requires reauthentication using the normal AWS CLI
login method; role assumption does not extend an expired source login.
This default is for new setup; it does not migrate existing teams or retarget
their original administrator receipts. Keep their original profile available
for guarded recovery/removal; do not rewrite receipts to switch identities.

Using an administrator-capable source does not make that source least-privileged:
it retains its existing permissions. Ordinary ZDN operations still require the
recorded deployment-role identity rather than silently falling back to source
administrator credentials.

Setup completes the S3/KMS bootstrap first. It then creates the protected
`zdn-access` Pulumi stack under `zdn-admin/v1/BOOTSTRAP-ID` in the same bucket.
This stack owns a deployment role, its scoped managed policies, the runtime
data policy, and a runtime permissions boundary. Stable names include the backend's bootstrap UUID.
Network stacks cannot write this administrator prefix or change their deployment
role, its policies, or the boundary. Network teardown preserves all these shared
resources. [Administrator team removal](removal.md#remove-an-originally-created-team)
requires original creation receipts, stopped writers, and closure of all owned
networks, builds, participant grants, and retained data. Imported profiles do not
authorize backend deletion.

Trust accepts explicit same-account IAM user or role ARNs, including Identity
Center role paths. It rejects account roots, STS sessions, wildcards, duplicates,
and self-trust. Locally invalid trust settings fail before backend creation.
Setup does not change IAM users, SSO permission sets, or organization
policies. It prints the exact caller-side `sts:AssumeRole` grant if the final
developer check fails; that grant is needed only if caller access is missing.
After IAM setup, the developer backend check retries typed `403`, `AccessDenied`,
and `AccessDeniedException` errors while new permissions propagate. The retry
window is 60 seconds, with delays of 1, 2, 4, 8, then at most 15 seconds. An AWS
request already in flight retains its own timeout. Ctrl-C stops further attempts.
Configuration errors, expired credentials, and unclassified `CommandFailed`
errors return immediately, including credential-process failures that do not
preserve an AWS error code. Ordinary backend checks do not use this retry window.
Keep the completed IAM receipt and repeat the same setup if the check still
fails. Existing permissions on the source identity are not changed.

Repeat setup may keep the same `--export` destination when its complete validated
team definition matches the saved local profile and the final verified setup
result. Equivalent YAML/JSON formatting is accepted without rewriting the existing
bytes or permissions. Conflicting, malformed, non-regular or symlinked exports
are rejected before AWS calls; an existing export without its matching saved
profile is not adopted. New exports are published atomically with private mode
0600, without replacing a concurrently created file. A repeated setup still
requires `--yes`, validates AWS/backend ownership, and does not skip IAM checks.
Keep the original team file, local profile, and receipts for recovery.

The exported version 2 contract adds this field beside `aws` and `state`:

```yaml
deployment:
  roleArn: DEPLOYMENT-ROLE-ARN-FROM-SETUP
  management: zdn
  runtimeBoundaryArn: BOUNDARY-ARN-FROM-SETUP
```

Legacy `zdn-team/v1alpha1` exports and deployments retain their existing behavior.
Setup does not convert an existing local profile between these access modes or
retarget its networks. Start a new team setup for the version 2 path. Team fields
remain strict; tokens and profile names are excluded from the shared export.

### Profile selection

A **zdn profile** binds a saved team definition to a developer's **AWS profile**;
the two names are separate. `--profile` selects the local zdn profile, while
`--aws-profile` selects credentials where that command supports it. Neither is a
global flag. Setup saves the explicitly selected AWS profile. Config-based render
and launch use `profile` from `devnet.yaml`; saved selectors such as status,
health, destroy, list and `up --saved` use their command's `--profile`, defaulting
to `devnet`. Connections and endpoint exports also default to zdn profile `devnet`;
participant `--endpoints` connections instead require an explicit `--aws-profile`
and do not use saved local profiles. Changing selection does not retarget an
immutable saved deployment or rewrite its team/backend identity.

### Daily credentials

Each developer imports the team file with their own source profile. Every live
foundation path uses that profile to assume the recorded role: direct AWS calls,
reservations, leases, status, teardown, Pulumi S3 state, KMS secrets, and the AWS
provider. The CLI verifies the assumed account and role.

A private AWS config invokes `zdn` as an AWS `credential_process`. A separate
empty credentials file prevents static credentials with the same profile name
from bypassing that process. The helper restores the original source config
and credentials paths, requests a one-hour STS session, and returns it directly
to the requesting SDK. Expiration permits SDK refresh during long operations.
Each invocation requests a fresh session; zdn has no token cache. Missing,
expired, or nearly expired credentials are rejected. Only non-secret instructions
are saved. AWS API stdout and stderr are captured through bounded in-memory pipes,
including credential responses. Credential errors omit raw AWS diagnostics. AWS controls revocation
and the lifetime of already-issued sessions.
[AWS process credential provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html).

The SDK command parser requires absolute paths with ASCII letters, digits,
spaces, dots, hyphens, underscores, or slashes for the zdn executable and its
private credential directory. Unsupported paths fail explicitly. Spaces use
backslash escapes without outer quotes, so both the AWS CLI and Pulumi SDK INI
parsers preserve the command's argument boundaries.
Long-operation SDK refresh requires separate live qualification. The source AWS config stays in
place and continues to support AWS CLI login/SSO profiles.

### Permissions and recovery

The deployment policies scope state object access to the team's devnet and
metadata prefixes, KMS use to its key, and EC2 mutations to owned resources in
its account and region. Ownership tags cannot be added to foreign resources or
changed by ordinary tag updates. Bucket listing and the necessary EC2/SSM read
APIs expose broader inventory. The deployment role also grants
`ssm:ListCommands`, `ssm:GetCommandInvocation` and `ssm:CancelCommand` on
`Resource: "*"`, restricted only by requested region. Without external denies,
these credentials can list commands, read their output and attempt cancellation
beyond ZDN-tagged hosts. CLI ownership filters do not restrict direct credential
use. Cancellation does not guarantee that the remote command or process stopped.
This exception concerns the deployment role, not participant or node-runtime
roles. Use a dedicated development account with trusted deployers; do not assume
strong isolation between unrelated teams in one account. AWS's
[SSM authorization table](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ssm.html)
does not list resource types for those three command APIs. Unsupported tag
conditions are not a substitute for account separation or a mediated control
plane.

EC2 launch also needs image and network-interface authorization for `RunInstances`.

Explicit artifact cleanup has `s3:DeleteObjectVersion` only under
`TEAM_METADATA_PREFIX/artifacts/*` in the team bucket. S3 requires this permission
for [deletion by version ID](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html),
including delete markers. Historical Pulumi state, leases, reservations, and
administrator state have no version-deletion grant. Existing teams must repeat
administrator setup to update this policy; node runtime roles cannot delete
artifact versions.

Version 2 sets the three ownership tags as provider defaults. The pinned provider
sends these tags with the root-volume launch request, before IAM checks them.
The root block device keeps only its other tags, so later tagging does not replay
immutable ownership keys. The separately managed chain volume keeps its own name
and resource tags. Existing hosts preserve their saved ownership-tag inputs during
updates. Older partial stacks with no provider defaults can retry or tear down;
conflicting saved defaults still fail validation.

Runtime roles use a bootstrap-specific IAM path. Creation requires the approved
boundary; attachment permits only `AmazonSSMManagedInstanceCore` and the exact
shared runtime data policy. PassRole permits only these runtime roles and EC2.
The boundary permits SSM registration/channels, team artifact reads and scoped
KMS decryption, and team ECR pulls. It excludes state, IAM, and parameter-store
access. Developers can inspect the boundary and data policy but cannot change them.
See [node access and qualification](private-devnet.md#access-and-tests).
The AWS-created default security group remains unmanaged. Health-test hosts have
no inbound rules; node hosts accept P2P only from exact cluster member addresses. This avoids
giving developers permission to adopt arbitrary untagged security groups.
[AWS permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html).

Cleanup also permits `iam:GetRole` on the same-account resource pattern
`role/zdn-*-host-role` and `iam:GetInstanceProfile` on
`instance-profile/zdn-*-host-profile`. After deletion, AWS must authorize the
name lookup before it can return `NoSuchEntity`. These read allowances can also
expose existing matching identities. IAM wildcards can span path separators, so
the patterns are not strict path-only ownership checks. They add no list or
mutation access and do not match the generated administrator deployment role.
Runtime mutations still require the bootstrap-specific path. An actual
`AccessDenied` response remains an error; cleanup does not treat it as absence.

`profiles/PROFILE.access/access.json` records the exact administrator request
before IAM effects. Repeated setup uses the same names. An uncertain stack
operation requires `--reconcile`, which selects and refreshes the existing stack
before a new saved preview plan. Ctrl-C uses the Pulumi runner's graceful
shutdown. A stack without its original ownership receipt is not adopted.
Preserve the setup directory and receipts. A resource created without recorded
Pulumi state can require administrator recovery; do not delete receipts to retry.
Changed trust or policy requests are refused by the recovery path; administrator
update/membership tooling remains separate work.

IAM recovery preserves the boundary identity and Pulumi protection recorded in
the owned checkpoint; it never renames, deletes, or repurposes that policy.
New setup uses `-runtime-boundary` for the boundary and `-runtime` for the
management policy. A supported legacy checkpoint may instead identify the
boundary as `-runtime`; recovery retains that ARN and uses
`-runtime-management` for the management policy. Detection accepts only the
exact supported legacy or current boundary document, never a management policy.
Repeating administrator setup adds the scoped team artifact/ECR permissions.

Setup chooses these names from the validated, owned Pulumi checkpoint after
refresh. It checks policy identity, path, ownership tags, protection, and the
legacy boundary document. Pending operations or conflicting identities stop
recovery. The access receipt saves `selected_access` before apply, so retries
cannot change the chosen boundary. The team export carries that ARN to daily
deployments, host roles, and repeat setup. The saved-plan gate still refuses
replacement or deletion.

Offline team validation accepts either exact managed ARN layout so a recovered
team can be imported without its administrator's local receipt. This validates
the identity format, not the purpose of a policy in AWS. Do not edit the boundary
ARN to choose a layout. Bootstrap checks the checkpoint; the deployed role's IAM
conditions enforce the boundary it approved. A forged layout can pass the offline
schema check and then fail with `AccessDenied` during deployment.

Recovery cannot detect a policy that exists in AWS but is absent from the Pulumi
checkpoint. This can happen after a lost creation result or manual removal of
pending operations. An `EntityAlreadyExists` response still requires administrator
inspection and recovery of the original state; setup does not adopt the policy,
change its purpose, or delete it to make the retry pass.

For an existing organization role, add `--existing-role-arn` and
`--runtime-boundary-arn`. Setup reads its exact ARN, explicit trust statements,
and boundary identity, then verifies developer assumption and backend access.
It records `management: external` and never renders, imports, changes, or deletes
that role or its policies. The organization remains responsible for its policy
contents. Inspection and a successful backend read do not prove every deployment
permission; actual foundation launch and denial checks require live qualification.

For an existing backend export, `zdn setup role-plan --from team.yaml
--aws-profile zcash-setup --trust-principal IAM-ARN` prints the proposed Pulumi
program, administrator backend, and caller grant without AWS calls or file writes.
Its output is marked `proposalOnly`, with `checkpointChecked: false` and a
`namingSource` of `defaults` or `teamDefinition`. Without a completed team export,
recovery may resolve different names from the owned checkpoint. The generated
local project is also provisional until that check.
The actual saved Pulumi preview uses the resolved names before apply and keeps
the prepared provider unchanged.

## Current qualification boundary

Backend verification accepts AWS's optional `BlockedEncryptionTypes` response
for either documented SSE-C setting. It still requires the exact team KMS key,
`aws:kms`, and enabled bucket keys. Retry reuses the original bucket and key
from the bootstrap receipt.

The deployment role covers the team's networks. Separate teams/bootstrap IDs
define its isolation boundary; per-developer network isolation is not provided
by that role. [Participant setup](connections.md#grant-participant-access)
creates a separate narrow access role.

Status does not verify the shared backend. It reports
`sharedBackendChecked: false` and inventory `shared_backend_preserved: null`.
Completed destroy cleanup receipts verify preservation and report `true`.
Teardown still checks account, region, bucket ownership and exact enabled KMS
identity, but permits setup-policy and default-setting drift when actual state
access works. It does not change those settings. Setup, import and launch keep
their strict checks.

See the contributor [test coverage notes](testing.md#subsystem-coverage-notes).
