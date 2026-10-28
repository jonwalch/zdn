# Light-wallet diagnostics and service preparation

The private devnet lifecycle connects lightwalletd to nodes. It saves exact image
inputs, allocates a separate cache disk, measures the selected host, installs the
service through SSM, and requires a fresh gRPC readiness result.

Wallet and faucet settings must remain `false`. Existing node-only requests are
immutable; use a new binding to enable this service. See the
[private deployment flow](private-devnet.md) for shared prerequisites and cleanup.

The candidate is lightwalletd **v0.5.5** with light-wallet protocol **v0.5.0**.
Its source includes Ironwood compact actions and tree data.
See the [compatibility record](lightwalletd-compatibility.md)
for exact source and image identities, evidence, and remaining live checks.
Neither source support nor an empty Ironwood tree establishes wallet compatibility.

## Connect a local client

After a new client-enabled devnet finishes deployment, run:

```sh
zdn connect my-feature
```

Use the printed gRPC address for the local wallet or SDK. Disable TLS for this
localhost connection; AWS Session Manager carries the private connection to the
host. The command also exposes node RPC through the restricted client proxy.
Keep it running while the client uses these endpoints. Ctrl-C closes the
connections and leaves lightwalletd and the nodes running.

The command checks the expected node and chain identity, then compares the
light-wallet service's latest block with node RPC. It does not perform a full
wallet scan or establish payment compatibility. Ironwood funding, submission,
and later spending remain pending.

Use `zdn endpoints` and administrator `zdn setup participant` for another person.
Their connection uses their own AWS identity and needs no node cookie,
deployment permission, or Pulumi-state access. Older saved requests with
`clientAccess: false` require a new devnet binding. See
[private client connections](connections.md) for the commands and access limits.

## Inspect an existing endpoint

Use an existing local node and lightwalletd endpoint, or already established
private tunnels. The command accepts numeric loopback endpoints only. The
diagnostic uses the node's administrative RPC, and its cookie must be in a
private file. Participant endpoint files never include that cookie.

```sh
zdn lightwallet readiness \
  --manifest chain-manifest.json \
  --rpc-endpoint 127.0.0.1:18232 \
  --cookie-file /private/path/node.cookie \
  --grpc-endpoint 127.0.0.1:9067
```

The check compares parsed node rules and saved history with the manifest. It
then checks the light-wallet protocol, activation height, consensus branch,
tip, compact block hashes and shielded transaction fields, commitment-tree
sizes, and Sapling, Orchard, and Ironwood tree state. It rechecks node history
before returning. A chain label or an open port is insufficient.

The default permits no tip lag. `--max-lag-blocks` can allow up to 1024 blocks.
Every check still requires the saved chain history and Ironwood activation.
The observation covers at most 62 saved heights plus two recent blocks. It does
not scan the full chain. `--request-timeout-secs` and `--deadline-secs` bound
individual calls and the whole observation, including stream completion.
Incorrect or incomplete data produces an error without a success report.
Transient transport failures, including the final node-rules request, retry the
complete observation within the same deadline. Authentication errors and rule
mismatches fail immediately.

The JSON report states the exact checked tips, lag, number of compact blocks,
and number of Ironwood actions observed. An empty chain can have zero actions.
It always retains `launchReady: false` and `paymentQualification: pending`.
It does not submit transactions, mine blocks, or qualify note scanning or proofs.

## Render a candidate private service

```sh
zdn lightwallet render-service \
  --host-spec node-host.json \
  --service-spec lightwallet-service.json \
  --output lightwalletd-recipe.json
```

The host input is a `HostInstallSpec` for the intended node. The service input
pins its source revision, private ECR image digest, dedicated cache EBS volume,
disk size, CPU and memory limits, and observed host capacity. The renderer
rejects overlapping node, service, and host-reserve budgets. Contract bounds
are not measured sizing recommendations. Existing immutable host installations
cannot be resized by this command.

The output contains Docker arguments, cache identity, paths, content hashes and
remaining requirements, not an executable supervisor. The optional JSON file is
created without replacing an existing output. Rendering allocates no disk, pulls no image,
installs no files on a host, and starts no process. The result retains
`deploymentReady: false`, with the remaining installation requirements listed.

The candidate service uses loopback gRPC and HTTP, a non-root container, a
read-only root filesystem, explicit resource limits, and its own cache disk.
The supervisor checks the expected cache mount and identity before Docker use;
it never formats storage or adopts a foreign container.

lightwalletd reads static RPC credentials at startup. The supervisor reads
Zakura's current cookie, writes a private runtime configuration, and restarts
lightwalletd when the cookie changes. Node authentication stays enabled.
Credentials are excluded from rendered artifacts, command arguments, and
reported errors. Restart and cancellation preserve the cache and clean up the
owned container and runtime credential file.
See the [service contract](lightwallet-service.md) for the exact file, resource,
and cleanup boundaries.

## Deploy with nodes

Create a fresh config with
`zdn init --image NODE_IMAGE@sha256:DIGEST --service-preset lightwallet`, replacing
the placeholder with the pinned node image from `image.json` used below.
This sets `services.lightwallet: true`, `services.wallet: false`, and
`services.faucet: false`. Supply a candidate image in the team's regional
ECR namespace, its exact child manifest and configuration bytes, and a record
that follows the [image contract](lightwalletd-compatibility.md#container-metadata).
The Linux host helper must be built from this implementation and support
`zdn-host-capacity/v1alpha1`. Fresh source builds additionally require
`zdn-build-export/v1alpha2` for metadata-only native result export.

```sh
zdn lightwallet verify-image --record lightwallet-image.json \
  --manifest lightwallet-image-manifest.json --config lightwallet-image-config.json
zdn devnet render --ami-id ami-REPLACE --availability-zone us-east-1a \
  --manifest manifest.json --bundle chain.tar \
  --image-record image.json --image-manifest image-manifest.json \
  --image-config image-config.json --host-helper ./zdn-linux-x86_64 \
  --reward-address YOUR-TESTNET-REWARD-ADDRESS \
  --lightwallet-image-record lightwallet-image.json \
  --lightwallet-image-manifest lightwallet-image-manifest.json \
  --lightwallet-image-config lightwallet-image-config.json
zdn devnet up --yes
```

`render` saves all nine artifacts. Later `up` calls use those saved copies.
Metadata checks prove byte identity and declared platform, not source provenance
or wallet compatibility. The service runs on node 2 when present, otherwise on
node 1. gRPC and metrics listen only on localhost. `zdn connect` manages
private tunnels for node RPC and light-wallet gRPC.

The initial service budgets are unqualified bounds:

| Preset | Separate cache | Service RAM | Service CPU |
| --- | --- | --- | --- |
| Small | 20 GiB | 512 MiB | 250 milli-CPUs |
| Medium | 40 GiB | 1 GiB | 500 milli-CPUs |
| Large | 80 GiB | 2 GiB | 1000 milli-CPUs |

Before the selected node is installed, a durable SSM command reads effective
memory, CPU affinity, and cgroup limits. The receipt binds the observed capacity
to the instance and immutable request. The node budget leaves space for the
service and host reserve. Retries reuse these limits; they do not resize a
running node. The supervisor checks the current aggregate budget again.

Fresh CLI requests save the native capacity protocol, including before an initial
source build. Capture downloads the content-pinned helper using the existing
artifact permissions, verifies its bytes and capability, and invokes Rust after
the host prerequisite marker is ready. Retry and controller handoff preserve this
selection and exact command history. Legacy requests cannot be upgraded by
resupplying inputs; they remain inspection and cleanup data only. Capacity
capture, host installation, and service supervision use the pinned native helper.

A fresh installation first validates every node, then starts the producer,
then installs lightwalletd. The service needs a positive block height and
Ironwood activation. Readiness permits at most two blocks of lag and checks
actual compact blocks and tree state. It keeps payment qualification pending.

Install and start commands have durable SSM journals. A lost reply is reconciled
before another command can run. A saved start command is settled before a new
health observation because both operations take the same host lock. A previous
success still needs fresh health evidence. A known stopped service can restart
with its saved image, cache, and limits. Add `--reconcile` after an uncertain
operation. A cache is formatted
only with saved creation authority; an unknown disk or uncertain format is
preserved. Reboot preparation remounts an already claimed cache without formatting.

Default teardown retains the cache. `destroy --delete-data` deletes it only when
the saved ID, ownership, and disk attributes still match. A changed tag cannot
hide a saved leftover from inventory. Shared state and IAM resources remain.

## Wallet compatibility

A ready lightwalletd service does not prove that a wallet supports this custom
Testnet. Check the selected wallet's ability to receive, scan and spend Ironwood
payments, including after a restart or reorg. See the
[chain and client checks](compatibility.md).
