# Private lightwalletd service recipe

`zdn lightwallet render-service` prepares an offline service recipe. It does not
create resources, install files, enable a service, or qualify Ironwood support.
Both `deploymentReady` and `launchReady` remain false for this standalone recipe.
The separate [devnet lifecycle](lightwallet.md#deploy-with-nodes) installs the
same service with saved image inputs, cache authority, and SSM journals.

The recipe selects the lightwalletd v0.5.5 command contract at commit
`d16d48124e9ad4157ebc2324b5090c6ba201470c`. It requires a digest-pinned image in
the node's account and regional private ECR registry. The digest, declared source
revision and native image architecture are separate checks. A declared revision
does not establish that an image was built from that source. See the
[compatibility review](lightwalletd-compatibility.md) for the image candidate and
unresolved Ironwood protocol requirements.

## Render a recipe

```sh
zdn lightwallet render-service \
  --host-spec node-2-host.json \
  --service-spec lightwallet-service.json
```

The host input is the existing first-install `HostInstallSpec`. The service input
uses `zdn-lightwallet-service/v1alpha1` and contains the pinned image, source
revision, separate cache volume ID and size, memory and CPU limits, and effective
host observations. The output includes container arguments, immutable cache
identity, paths, hashes, and remaining requirements. An optional `--output`
writes that JSON recipe to a new file without replacing an existing file.
Native installation supplies the compiled supervisor and systemd unit separately;
this command does not install either.

Place one service on a selected existing node host. A follower avoids sharing
the producer's workload when three nodes are present. The recipe does not choose
or change that placement. Each host supports one service with gRPC on
`127.0.0.1:9067` and metrics HTTP on `127.0.0.1:9068`. There is no public ingress or
Docker port publication. The loopback gRPC transport uses plaintext;
[SSM tunnels](connections.md) provide the private remote connection.

## Authentication and restart behavior

The pinned upstream service cannot reload Zakura's cookie itself. The host
supervisor reads the cookie through no-follow file descriptors. It checks every
parent, the file owner, permissions, link count, size, and the exact Zakura cookie
format. It writes a private `zcash.conf` in `/run` by atomic replacement. The
file has mode `0400` and belongs to the unprivileged container UID. No credential
value is put in container arguments, environment variables, reports, durable
cache storage, or supervisor diagnostics.

The container gets a read-only credential directory. The supervisor checks for
cookie changes once per second. On rotation, it stops the owned container,
rechecks the node and cache identity, replaces the private config, and restarts
the same pinned image with the same cache. A missing or invalid cookie stops the
service. After cache and node validation, startup stops any verified owned
container left by an earlier supervisor before reading the current cookie. A
missing or invalid startup cookie cannot bypass that cleanup. Credentials are
removed even when shutdown fails. The wrapper suppresses
subprocess diagnostics; lightwalletd keeps its normal application logs without
debug credential flags.

The unit follows `zdn-node.service` with `BindsTo`, `PartOf`, and an install-time
`WantedBy` dependency. It has bounded restart attempts. The wrapper first asks
Docker for a graceful stop, then uses an owned-container kill if needed. It also
cleans the attached client's process group. Failed Docker cleanup is reported as
incomplete; an unavailable Docker daemon cannot be treated as successful cleanup.

The container uses UID 10001, a read-only root filesystem, no capabilities, no new
privileges, a PID limit, equal memory and swap limits, and a CPU limit. It checks
that the host's existing UID-based IMDS firewall rules are present. It mounts
only the service cache and read-only credential directory. It does not mount the
node's state, the Docker socket, or the host filesystem.

## Resource and storage boundaries

The node budget must leave explicit room for lightwalletd. Rendering rejects a
sum of node memory, host reserve, and service memory above the smallest measured
host/cgroup limit. It also checks CPU visibility, affinity, every finite parent
quota, and the 250 milli-CPU host reserve. A host whose node already consumes all
available application resources must have its node budget reduced explicitly.
The live supervisor rechecks these bounds and the running node's actual limits.
It ignores only its own known systemd leaf when measuring shared host capacity.

The service bounds of 256 MiB and 250 milli-CPUs are input-validation limits,
not recommended or qualified sizes. The wrapper's own 128 MiB and 100 milli-CPU
ceiling comes from the existing host reserve. This work does not prove a useful
production memory, CPU, or storage size.

The cache requires a separate 1–2048 GiB EBS volume. The upstream service has no
cache-size flag, so an ordinary directory on the node's chain volume would not
enforce the stated disk budget. The recipe identifies the separate disk by EBS
serial, exact byte size, filesystem, mountpoint, mount options, and a private
identity file. The dedicated filesystem must be ext4 with
`rw,nodev,nosuid,noexec`, mounted only at the rendered cache root. Its `data`
directory must belong to UID 10001 with mode `0700`.

The supervisor never formats, mounts, claims, or deletes a disk. It fails before
any Docker call if the expected mounted disk and exact identity are absent.
The deployment installer handles allocation, authorized initialization,
retention, deletion and SSM recovery. Reboot preparation only remounts a claimed
cache. The installation identity binds the first-install image and budgets;
changing them in place is unsupported. An open gRPC port is not a readiness result.

For contributor checks, see the [test coverage notes](testing.md#subsystem-coverage-notes).

The command flags and `.conf` keys come from the pinned upstream
[command implementation](https://github.com/zcash/lightwalletd/blob/d16d48124e9ad4157ebc2324b5090c6ba201470c/cmd/root.go)
and [RPC configuration parser](https://github.com/zcash/lightwalletd/blob/d16d48124e9ad4157ebc2324b5090c6ba201470c/frontend/rpc_client.go).
The explicit native entrypoint follows its
[Dockerfile](https://github.com/zcash/lightwalletd/blob/d16d48124e9ad4157ebc2324b5090c6ba201470c/Dockerfile).
