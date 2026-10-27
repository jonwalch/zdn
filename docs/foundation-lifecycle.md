# Foundation operations and recovery

The foundation runs one harmless test service. It does not consume the selected
Zakura source, build an image, or launch the configured three-node chain.
The config supplies the local team profile, network label and host size. The
first render also needs an exact AMI and Availability Zone. The saved request
keeps those host settings fixed. Labels can change without replacing resources.

## Saved state and concurrency

The local state directory contains imported profiles and one foundation
directory per full network UUID. The foundation receipt saves the exact team,
backend, provider profile, AMI, AZ, size, reservation owner, outputs and most
recent operation. Keep this directory for retries and disk recovery. The saved
team and host settings cannot silently retarget an existing deployment.

A local file lock permits one writer per foundation. A separate profile lock
protects setup and import. Metadata paths must be regular files; symlinks and
special files are rejected. Writes are atomic and flushed before cloud effects.
`foundation status` reads the latest published receipt without taking the
deployment writer lock. It works during apply or destroy. Its receipt and cloud
results are snapshots and can change while the command runs. Use `lastOperation`
from its output with `receipt inspect` or `receipt cancel` in another terminal.
Both status commands report `sharedBackendChecked: false` and inventory
`shared_backend_preserved: null`: resource inventory does not check the shared
backend. A successful destroy receipt separately records verified preservation.
Instance inventory projects only IDs and lifecycle states before bounded AWS
output capture, so multi-node EC2 metadata does not overflow the capture limit.
Tag-scoped discovery and exact saved-ID lookups both use that projection.

An S3 reservation binds the UUID to its original owner. A conditional S3 lease
protects each cloud operation. It lasts 15 minutes and renews every 30 seconds
during Pulumi and host polling. Each process uses a fresh holder ID. Pulumi's
own backend lock also protects infrastructure updates.

A transient renewal failure is retried after 2, 4, 8, 16, then 30 seconds.
The last confirmed lease remains the authority during retries. A lost renewal
reply is recovered only when S3 contains the exact attempted record. Permission
failures and changed ownership stop the operation immediately. Work also stops
before starting a renewal with 180 seconds or less left; it checks that budget
again when the requests finish. This reserves time for bounded AWS requests and
Pulumi shutdown. Both wall time and monotonic time limit the lease. A clock
adjustment cannot add time to the confirmed lease.

Cancellation reads try the local metadata lock without waiting. Brief contention
does not interrupt Pulumi or prevent lease renewal. If the state stays busy for
30 seconds, the operation stops. Invalid or unreadable state stops it immediately.

## Apply and readiness

`foundation up --yes` first saves an operation receipt. Each phase is marked
running before its effect. The phases check identity, reserve the ID, acquire
the lease, prepare the stack, preview, apply, and check readiness. A stack is
created only when structured discovery shows it is absent and the saved request
has never initialized it. An unexpectedly missing initialized stack stops apply.
Preview saves a private Pulumi plan. Apply must use that unchanged plan and cannot
silently replace or delete resources. Host setup changes that require replacement
need explicit teardown and a new network. See [update plans](pulumi.md#stack-operations).

Pulumi success is not host readiness. The CLI waits for SSM and runs a bounded
native helper HTTP probe on the host. It checks the network UUID, mounted disk, active
Docker/SSM services, and effective CPU/memory budgets. Readiness runs after an
unchanged apply too. A failed readiness check preserves the recorded host outputs.

Ctrl-C stops local work. `receipt cancel OPERATION_ID` also stops new phases and
is checked during Pulumi callbacks and host polling. These actions do not roll
back resources that AWS has created. A failed or interrupted mutation is recorded
as uncertain and needs reconciliation.
A concurrent cancellation request is preserved when the running phase records
its outcome. A separate state revision changes on phase writes, reconciliation
and retries, but not cancellation. This rejects an old attempt even when a later
attempt returns the phase to `Running`. Old receipts load this counter as zero
and acquire it on their next phase write. A completed effect can retain success,
but cancellation prevents the next effect from starting.

The runner allows the CLI up to 30 seconds for checkpointing, then stops remaining
plugin groups in the run's private OS session. A five-second cleanup check must
finish before the lease is released. A missing cleanup acknowledgement retains
the lease and blocks another local run; see [process supervision](pulumi.md#bounds-cancellation-and-diagnostics).

## Interrupted operations

Inspect the operation and current cloud inventory:

```sh
zdn receipt inspect OPERATION_ID
zdn foundation status NETWORK_ID
```

If the private project file `.zdn-pulumi-process.json` has no completion, inspect
and stop the old CLI and any owned plugins, then archive that receipt before
retrying. Establish current ownership before signalling a saved PID. Resolve the
Pulumi lock only after all old workers have stopped. Do not signal unrelated processes or remove a lock while an old mutator
can still run. After inspecting the resources and resolving that lock, retry with `foundation up --yes --reconcile` or
`foundation destroy NETWORK_ID --yes --reconcile`. Reconciliation refreshes an
existing stack before another apply or destroy. The outstanding uncertainty
remains recorded if a retry fails before reconciliation or completion.

An expired S3 lease is not taken over automatically. Stop the old operation,
inspect the lease returned by `foundation status`, and pass its exact ETag with
`--recover-lease-etag ETAG --reconcile`. A changed ETag or an unexpired lease
rejects recovery. This does not break a Pulumi lock. Do not remove a remote lock
while its owner may still be running.

Acquisition retries a transient failure at most three times within the same CLI
attempt. Every retry uses the same holder, expiry, generation and conditional
write. An exact readback recovers a lost success reply. A changed record stops
acquisition. If those bounded checks all fail, or the process exits, inspect the
lease: a later CLI attempt uses a new holder and cannot reclaim an active lease.

Bootstrap has its own recovery receipt and KMS recovery option. See
[backend recovery](aws-state.md#setup-and-recovery).

## Teardown and data

`foundation destroy NETWORK_ID --yes` previews destruction and removes the
stack's host, root disk, IAM runtime resources and network. The data disk uses
Pulumi retention. With `--delete-data`, the CLI then checks its exact identity,
tags, AZ, encryption and detached state before requesting deletion. The operation
kind and input digest record the data-deletion choice before any cloud effect.
When apply did not save outputs, teardown first saves exact volume identities
from the validated Pulumi checkpoint. Tags alone do not authorize deletion.
That receipt survives stack removal for a later explicit data-deletion request.

The pinned provider can try to disassociate an Elastic IP after deleting its
NAT gateway. For that exact denied operation, zdn verifies the saved allocation
and association, current ownership, an unassociated address and completed NAT
deletion. It then refreshes state, checks that the stale association is cleared,
and retries destroy once under the same lease. A sanitized
`stale-address-recovery.json` records the evidence. Other failures retain the
normal explicit reconciliation path.

Teardown verifies the backend account, region, bucket ownership and exact KMS
identity. It does not require setup policy, encryption defaults, versioning or
rotation settings to remain byte-for-byte unchanged. It leaves those settings
alone; actual state access must still work. Setup, import and launch retain the
strict backend checks.

Cleanup checks actual EC2, EBS, address, NAT, VPC, subnet, route, security-group,
gateway, role and instance-profile results. It looks up every saved host, VPC,
private subnet, security group, NAT, address and data disk by ID as well as tags.
Removed or changed tags cannot hide these known resources. Exact lookups must
return the selected ID or a resource-specific absence error; permission errors
and incomplete responses stop cleanup. A resource with changed ownership stays
in the remaining inventory and requires inspection. Incomplete cleanup keeps
its result and reports failure. Direct lookup does not authorize deletion.

Explicit node-artifact deletion lists ten versions or delete markers per request,
deletes those exact versions, and relists to prove emptiness. The existing
100-page work bound and prefix/owner/partial-error checks remain in force.
This keeps ordinary update history within bounded AWS response capture.

Empty stack state is removed only after cleanup succeeds. A retry after stack
removal still checks cloud inventory and finishes requested data deletion. This
also permits a later `destroy --delete-data` for a previously retained disk.
The shared backend, KMS key and reservation remain. Retained disks and shared
storage continue to cost money.

A destroyed foundation cannot be silently recreated with its old UUID. A fresh
configuration path or branch gets a new local binding. Restoring a retained disk
into another deployment is a separate operator action; no automatic disk restore
or cross-machine foundation-receipt import is implemented yet.
