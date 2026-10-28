# Scheduled blocks

Private deployments start one Rust block controller on node 1. The default
interval is 25 seconds. Set `network.mining.interval` in `devnet.yaml` before
rendering the deployment. The accepted range is 1 to 86400 whole seconds. The
saved request pins this value. Existing node-only requests without a saved
interval remain unscheduled.

The controller calls authenticated `generate(1)` on loopback. Zakura's internal
miner stays disabled. Each tick checks effective consensus rules, saved history,
the actual tip, and a matching mining template. A slow call skips missed ticks;
the controller does not issue a burst to catch up. The interval is a target,
not a block-time guarantee.

## Start and stop

`zdn devnet up --yes` first installs all nodes and obtains a fresh readiness
observation from each. It then sends one journaled SSM activation command to
node 1. Activation is part of the install phase, so an uncertain result requires
`--reconcile`. A lost command response is recovered from the same command journal.
The final readiness phase observes every host again and requires a live producer.

If a previously activated producer stops, repeat `devnet up --yes`. The tool
first recovers any uncertain activation command, then checks current health.
If the producer is still stopped, it records one new start attempt in the same
command journal. The host clears systemd's failure counter before starting a
stopped service, so recovery also works after the restart limit is reached.
It preserves the block journal and any unresolved generation intent. An unknown
command is never replaced just because the service appears stopped. The SSM
history keeps the existing limit of 32 attempts; exhaustion requires inspection.

The root-owned activation marker is on the chain EBS disk. Systemd runs the
controller independently of the local CLI. It orders the controller after node
startup and stops it before a node shutdown or restart. Each new install also
saves a bootstrap-complete marker only after seed loading and readiness succeed.
Later starts check actual history without submitting the seed blocks again.
Missing or changed history fails readiness.

The producer has a 128 MiB memory cap and 10% of one CPU, within the host
reserve. It can write only its private state directory. Followers do not start
this service and reject an observed active controller.

Systemd gives the producer directory its own writable bind mount. The controller
checks the exact EBS device, target, filesystem root, ext4 type, and safe mount
options inside that namespace. Installation and formatting keep their stricter
rule against extra mounts.

For a separately managed node, the controller can be run directly:

```sh
zdn chain produce --manifest manifest.json \
  --rpc-endpoint 127.0.0.1:18232 --cookie-file /private/path/.cookie \
  --state-dir /private/path/producer --deployment-id DEPLOYMENT-UUID \
  --node-id node-1 --interval-secs 25
```

Use an RFC 4122 version 4 deployment UUID and an existing private parent directory.
Complete bootstrap first. Disable the internal miner and all other producers.
Keep the same state directory across restarts. `--max-blocks N` bounds a diagnostic
run; the systemd service has no block-count limit. SIGINT and SIGTERM stop after
the current bounded RPC and preserve uncertain work. Each controller process reads
the current cookie at startup. The host restarts the controller with the node,
so a new process reads the replacement cookie. An authentication error never
authorizes another generation request.

### Bounded unpaced history

For an explicitly approved bounded history run, add `--unpaced --max-blocks N` to
`chain produce` to build real history without the scheduled wait before the first
block or between blocks. A positive block-count bound is mandatory. For example,
with the scheduled service stopped and the same manifest, identity and state:

```sh
zdn chain produce --manifest manifest.json \
  --rpc-endpoint 127.0.0.1:18232 --cookie-file /private/path/.cookie \
  --state-dir /private/path/producer --deployment-id DEPLOYMENT-UUID \
  --node-id node-1 --interval-secs 25 --unpaced --max-blocks 256
```

Use the interval pinned by the existing journal (25 seconds in this example).
It remains valid configuration and journal metadata but
does not pace an unpaced invocation. The mode is explicit per invocation, not
persisted: omitting `--unpaced` restores normal scheduling. Host services remain
scheduled and unchanged.

This is not a `generate(N)` batch: every block still uses `generate(1)`, a durable
pending intent, readiness and exact-tip checks, ancestry reconciliation, and a
durable receipt. Readiness and uncertain outcomes can still require bounded
polling waits. The bound counts confirmations in this invocation, including a
recovered pending intent, not total history or a persistent target. After an
interruption inspect status and recompute the remaining target; do not blindly
repeat the original count or erase the journal. A tip advanced outside the
producer is never silently adopted.

Unpaced operation changes no consensus or timestamp rules and makes no throughput
guarantee. It does not qualify scheduled timing or wallet history/payment/recovery
behavior. Live-node history and wallet acceptance require separate evidence and
explicit workload approval; local fixtures do not prove them. See
[testing boundaries](testing.md#external-system-acceptance). Do not replace the
helper or change saved inputs during an active run.

`chain producer-status` accepts the same `--manifest`, `--state-dir`,
`--deployment-id`, and `--node-id` arguments and makes no RPC calls. Host status
also compares the recorded owner PID with systemd's current PID. It reports
`scheduledProducer: true` only while the controller holds its lock and is waiting
or generating. A saved journal alone does not prove the process is running.
`devnet status` remains an inventory command; `devnet up` gets fresh readiness.

## Recovery

`generate(1)` has no retry key. Before calling it, the controller writes and syncs
the expected parent and a pending intent. It permits only one request at a time.
It confirms the exact next height, parent, best-chain hash, and block header. If
the RPC returned a hash, that hash must match too. Each confirmed block gets a
durable receipt before the pending intent is cleared.

A timeout can still have produced a block. The controller observes the chain
without submitting another request. A single matching descendant can resolve a
lost reply under the single-producer assumption. An unchanged tip does not prove
the request failed. If the bounded observation cannot resolve it, production
stalls and retains the intent. Restart checks that same intent again. Conflicting
hashes, ancestry, a reorg, or a tip that advances by more than one block stop
production. Do not delete the journal to make it resume. A missing journal beside
an existing ownership file or block receipts fails closed. This also stops an
interrupted first initialization that never finished writing its journal; inspect
the saved files before any manual recovery.

The file lock excludes another controller using the same state directory. It
does not fence an operator with authenticated mining RPC access, a controller
using another directory, or a replacement host. Automatic failover and binary
updates need their own coordinated workflow. This version refuses changed
installation inputs.

## Funding and payment limits

No funding warmup or coinbase-maturity target is implemented. Ironwood activation,
usable mempool behavior, wallet funds, and payments remain separate checks.
`paymentQualification` stays `pending` and `launchReady` stays `false`.

For contributor checks, see the [test coverage notes](testing.md#subsystem-coverage-notes).
