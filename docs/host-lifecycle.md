# Run a private Zakura host

The host installer supports a first install and an exact retry on Amazon Linux
2023 x86-64. It runs after Pulumi attaches the selected EBS volume and SSM is
ready. EC2 user data installs `docker`, `awscli-2`, `amazon-ssm-agent`,
`e2fsprogs`, and `util-linux`. It does not select a disk or start a node.

The deployment supplies an immutable `zdn-host-install/v1alpha1` specification:

- Deployment UUID, node ID, consensus fingerprint, and exact EBS volume ID.
- Exact runtime TOML and its SHA-256.
- A digest-pinned image in the team's regional private ECR registry.
- S3 references with owner account, region, exact size, and SHA-256 for the
  Linux x86-64 `zdn` helper, chain manifest and bundle, image record, and raw
  single-platform registry manifest.
- Node role, requested CPU and memory caps, and a memory reserve for the host.
- An optional pinned block interval. New requests use 25 seconds by default;
  old requests without this field remain unscheduled.

The renderer produces a shell script and its SHA-256. Rendering does not contact
AWS or establish that a host or image works. The deployment must verify uploaded
script bytes before it runs them through SSM. Artifacts stay in one team bucket;
downloads check the expected bucket owner and verify the exact bytes.

Package names follow the [AL2023 package inventory](https://docs.aws.amazon.com/linux/al2023/release-notes/all-packages-AL2023.12.html).
The container uses Docker's [host networking](https://docs.docker.com/engine/network/drivers/host/)
and therefore shares the host network namespace.

## Install and restart

The installer takes an exclusive host lock. It saves a root-owned installation
identity before changing the data disk. It downloads and verifies every artifact,
then uses the pinned Rust helper to re-render the runtime TOML from the downloaded
manifest. The result must match the exact requested TOML and fingerprint. It pulls
the pinned image with a temporary ECR login, validates the registry manifest and
Docker inspection, and removes the temporary registry credentials.

The installer finds the data disk by its exact Nitro EBS serial. It rejects
ambiguous matches, partitions, other mount points, unexpected filesystems, and a
mount that points to another device. It does not guess from `/dev/sdf` or a disk
number.

For a new deployment, the controller can authorize the first format of an exact
new EBS volume. It must record a creation intent before apply, then verify the
managed Pulumi checkpoint and AWS volume identity, creation time, size,
attachment, encryption, and absence of a source snapshot. It saves the resulting
authorization before installation and pins it in the immutable host
specification. Tags alone cannot authorize formatting. No additional AWS
permissions are granted to the host.

An authorized first format still requires no partitions, filesystem signatures,
prior claim, or previous format attempt. Linux counters for the exact block
device must show no writes, discards, or in-flight I/O. This path permits new
EBS blocks containing pseudorandom bytes, as described by
[AWS EBS data security](https://docs.aws.amazon.com/ebs/latest/userguide/EBSFeatures.html).
It does not guess whether unknown bytes look random. Without that authorization,
the existing scan requires only zero bytes across the entire reported size and
stops after 30 minutes. A timeout leaves the disk unformatted.

Before formatting, the installer saves a root-owned format intent. If an attempt
is interrupted and the volume is still raw or has an unknown partial filesystem,
it refuses another format and preserves the disk for inspection. For an
authorized first format, an ext4 filesystem with only an empty `lost+found` can
complete its interrupted claim only with the exact matching intent. After
claiming the volume, a second root-owned marker prevents it from being formatted
again even if its filesystem later disappears. Restart never authorizes a first
format.

The ext4 volume mounts at `/var/lib/zdn` with `nodev,nosuid,noexec`. A root-owned
volume identity binds it to the deployment, node, consensus, volume, and exact
installation specification. Existing data without that identity is refused.
An empty ext4 filesystem can complete an interrupted first install when its
root-disk installation intent still matches. The installer never resets a
database or formats an existing filesystem.

Configuration and manifests use create-only atomic writes. An exact retry can
reuse them. A changed image, configuration, resource request, artifact reference,
or identity fails with the old data preserved. Binary updates and replacement
hosts that adopt retained storage need their own recovery/update workflow.

The node runs under `zdn-node.service`. Each start performs these steps:

1. Verify artifacts and exact configuration again. Check or mount the same EBS
   volume and verify its identity. Check the local image.
2. Remove a stopped or orphaned container only when its name, image, and install
   label match this installation.
3. Start Docker with the pinned image. Wait up to 60 seconds for authenticated
   RPC with matching effective rules, then run
   [bootstrap and readiness](bootstrap-readiness.md) through the private cookie.
   New scheduled installs save a bootstrap-complete marker after both checks
   pass. Later starts check history without replaying seed blocks.
4. Mark systemd startup complete only after the actual chain passes these checks.

Systemd starts the node again after failure or reboot, with a bounded restart
rate. Shutdown sends SIGINT through Docker, allows 60 seconds, and retains all
EBS data. The separate `zdn-producer.service` starts only after all nodes pass
fresh readiness and an explicit SSM action saves its EBS activation marker.
Systemd orders it after node readiness and stops it before the node. Its durable
intent and block receipts survive restarts. See the [block controller](block-producer.md)
for uncertain RPC recovery and ownership limits.
If the producer exhausts its restart limit, a later `devnet up` can issue a new
journaled start after recovering the previous command and checking current
health. The host clears the failure counter only for a stopped service. This
does not clear pending block generation or change the chain data.

A retained cookie does not establish that RPC is available. The startup gate
reloads the cookie on each attempt and retries missing cookies, transport
failures, and HTTP 401 until its deadline. Unsafe or malformed cookies, incorrect
rules, and other protocol or RPC errors stop startup immediately. The gate only
reads rules; bootstrap still checks rules before it can submit saved blocks.

## Container and host limits

Docker runs the node as UID/GID `10001:10001`. It uses a read-only root filesystem,
drops all capabilities, applies `no-new-privileges`, disables image health checks,
and sets PID, CPU, and memory limits. The three writable binds contain only node
state, peer identity, and RPC cookie files. Configuration remains read-only.
The container has no Docker socket or AWS credentials mounted into it.

The launcher selects `/usr/bin/env -i` explicitly, followed by a fixed `PATH`,
`HOME`, and `/usr/local/bin/zakurad`. This clears inherited and image environment
settings, including `ZAKURA_`, `ZEBRA_`, and `OTEL_`. It overrides image entrypoint,
command, working directory, user, stop signal, and health-check defaults.

The actual memory cap is the smaller of the requested cap and effective host
memory minus the host reserve. Effective memory uses Linux `MemTotal` and every
finite cgroup v2 ancestor limit. CPU uses affinity and ancestor quotas, leaves
250 milli-CPUs for the host, and applies the requested cap. Less than 1 GiB or
250 milli-CPUs for the node is an error. Swap is disabled for the container.
These limits do not prove that a particular node build meets its own minimums.

Host networking keeps node RPC on numeric loopback and P2P on the configured
private IPv4 address. The AWS security group controls peer membership. Host
OUTPUT firewall rules block both EC2 metadata addresses for UID `10001`. The
installer checks these rules on every start and observation. This blocks node
access to the host role; IMDSv2 hop limits alone do not isolate host networking.

## Observe and retain data

The installed native host helper's `observe` operation checks installed inputs, the EBS
identity, and live chain readiness without submitting blocks. The result includes
deployment/config/image identity, the full readiness observation, and checked
Docker resource limits. It emits no cookie or ECR login value. It is a current
observation, not a permanent receipt that a later operation can trust.

The internal `ready` operation also loads saved history on first startup and
requires the local controller to be stopped. A completed bootstrap marker skips
submission on later starts. Observation reports producer health from its live
lock, phase, and systemd PID. Activation uses the separate `start-producer`
operation. All reports keep payment qualification pending and `launchReady: false`.

Installation has an 80-minute cumulative deadline, including downloads, image
pulling, disk scans, and service startup. Observation has a 250-second cumulative
deadline. Producer activation has a 650-second host deadline and a 720-second
SSM bound. Each subprocess also has a shorter per-command bound. Timeout or
termination stops its process group before the installer exits. A persistent
node that already reached systemd startup remains an identifiable managed
service; a lost installer response does not imply that it was removed.

Stopping the service or removing EC2 does not delete the chain volume. Pulumi's
retention setting controls whether teardown leaves the EBS resource. The host
installer contains no data-deletion operation.

For contributor checks, see the [test coverage notes](testing.md#subsystem-coverage-notes).
