# External public-chain contracts and host runtime

The separate local [external controller](external-controller.md) dispatches
launch, saved recovery, image/source updates, read-only health and destruction.
Neither controller nor host implementation is live-qualified.

This document records the original offline host/API slice. Ordinary deployments
keep their in-process adapter and original default serialization. They do not
require or download a companion. Explicit configuration can name
`chain: { kind: ordinary }`. An external selection contains `kind: external`,
`packageSha256` and `adapterSelectionSha256`. Configuration validation accepts
canonical explicit pins; ordinary chain, staging, source-render, launch and
update admissions refuse attempts to use external selections as ordinary chain
requests. The explicit external branch handles its own immutable inputs and
lifecycle dispatch. `check` and `plan` report unchecked prerequisites without
constructing an ordinary chain request or claiming live readiness. External
execution is Linux-only. This is not launch authorization.

## Implemented offline API

Linux `public_chain_adapter::VerifiedExecutable` retains its single-use pinned
snapshot, fixed argv, scrubbed environment, process-group cleanup, cancellation,
4 MiB output and 16 KiB discarded-stderr bounds. `invoke(Describe, ...)` retains
its five-second ceiling. Typed `compile` and `render` have thirty-second ceilings
intersected with the caller deadline. These local trusted-process controls are
not OS isolation, network denial, protection against same-user code, escaping
descendants or crash supervision.

`contract::CompileInput` has descriptor, exact native-rules/profile file strings
and a raw-bundle byte/hash pin. No arbitrary host paths, command hooks, build
environment maps or input attachments are accepted. Raw blocks are staged as
`seed-blocks.bin`, repeated little-endian u32 byte length plus raw block bytes.
Core verifies framing and exact byte pins independently; the companion must
decode the bytes as well. Metadata has a 2 MiB per-slot bound, aggregate requests
4 MiB, raw bundle 128 MiB/256 blocks, and per-saved-block limit 2,000,000 bytes.
A companion may retain a stricter native-tool limit. This is not maximum-sized
20 MB saved-history support.

The compile result binds native identity, full expected diagnostic data, native
upgrade/branch schedule (including implicit upgrades at shared heights), dense seed identities and byte pins, sorted bounded
Cargo features/capabilities and a finite transport class. Its compact typed
result bytes are pinned exactly, without the request ID/envelope. Both peers
must independently compile authenticated inputs and compare those bytes.
`PinnedResult` exposes only immutable references to its value, bytes and pin.
Upgrade heights are nondecreasing; names and nonzero branch IDs are unique.
The final row at each height must match the diagnostic's collapsed effective
schedule. Readiness compares the full list with blockchain-info upgrade
statuses and uses that same precedence for current/next-block branches.

Every request/response binds protocol, operation, fresh UUID and selection.
Compile/render additionally bind canonical descriptor SHA-256, full typed input
SHA-256, raw-bundle SHA-256 and optional compiled-result SHA-256. The full render
input binds deployment, node, role, exact image digest, runtime paths/listeners,
expected persistent public NodeId and cohort peer inventory. Strict parsers reject
duplicate keys recursively, unknown typed fields, floats, positional arrays in
place of typed objects, trailing JSON and mismatched bindings.

Before accepting rendered TOML, core independently constructs the supported
field envelope and checks complete structural equality. Extra tables/fields,
public/unauthenticated RPC, different cookie paths, state deletion, ephemeral
state, internal mining, secret-key overrides, native identity/listener changes
and NAT traversal cannot pass merely by being identical on controller and host.
Paths are exact `/var/lib/zdn/deployments/UUID/nodes/NODE/chains/DESCRIPTOR_HASH/`
state/identity/rpc leaves. Identity and cookie directories are separate from state.
Native peers must have distinct public hex IDs and numeric private endpoints.
Consensus semantics and native fingerprint computation remain companion-owned;
core has no node/wallet or TPQ dependency.

## Structural public package

`public_chain_adapter::package::PublicPackage::inspect` accepts an independently
supplied byte/hash pin and strict `zdn-external-package/v1` manifest. It opens
only these fixed regular non-symlink leaves, checks their bounds/hashes, and
never executes or downloads anything:

- `descriptor.json` (canonical typed bytes)
- `native-rules.json`
- `wallet-profile.json`
- `seed-blocks.bin`
- `host-adapter` (exact selected Linux host executable bytes)
- `compiled.json` (canonical exact result bytes)

`PublicPackage::from_json` validates only pinned structural metadata, without
opening any slot or requiring the companion. Future saved ownership/cleanup
readers can use this boundary separately from operational compatibility.

Source URL/revision/license and host platform are declarations, not publisher
authentication. Inspecting a package does not grant trust. Unknown manifest
fields and private-file/path slots refuse. This is an offline external public
inventory, not an extension of the existing ordinary six-file operational
artifact set. The external artifact set and saved deployment branch bind it
separately for installation, updates and recovery. Ordinary package admission
still refuses external inputs rather than silently interpreting their schema.

## Controller CLI and immutable external artifact branch

Linux exposes `zdn external inspect|compile|stage|verify|render|identity-manifest|host-manifest`.
`inspect` reads only pinned structural metadata, without opening an executable.
`compile` performs fresh explicitly trusted local recompilation. These controller
commands are trusted same-UID processes, not host sandbox execution.

`stage --public-directory ABS --trust TRUST_JSON --config CONFIG
--image-record IMAGE_JSON --image-manifest MANIFEST_JSON
--image-config CONFIG_JSON --host-helper HELPER --output NEW_DIRECTORY`
creates `zdn-external-artifact-set/v1` (`external-request.json`), a separate
versioned branch rather than invented ordinary consensus fields. An optional
`--build-contract` must already bind compiled features/capabilities through
`BuildContract::require_external`. Eleven fixed slots add the exact node image
record/manifest/config and Linux `zdn` helper to the public package. Source
selection, node count, cadence and configured build recipe/features must match.
Ordinary selection or ordinary wallet/lightwallet/faucet services refuse before
snapshot or adapter execution. Every staged input is checked before publication.

`verify --request REQUEST --sha256 SHA256 --directory ABS` rechecks all saved
bytes, the requirement-aware image proof, helper format and fresh compilation.
`render` accepts explicit public/trust/options/cohort files, an existing inventory
directory and exact inventory evidence pin. Only a complete same-chain cohort
can bind persistent native IDs/peers. Runtime config publication is create-only.

`host-manifest` accepts the pinned request/directory, fixed typed `--sources`,
`--options`, `--cohort`, `--inventory-directory`, `--inventory-pin` and new
`--output`. It independently recompiles and security-checks rendering, checks
every source pin against the immutable artifact set, and retains the inventory
pin in the resulting host manifest. It neither uploads objects nor starts hosts.

`identity-manifest` accepts the pinned request/directory, immutable `--provisioning`,
fixed `--sources`, peerless follower `--options` and new `--output`. Optional
`--bootstrap-output` saves the existing hash-checked helper-delivery/timeout
wrapper, selecting only `__external-native-identity --protocol
zdn-external-native-provisioning/v1`. Rendering this script does not execute it.
The identity manifest and final runtime manifest are different typed contracts.

## Transport classes

`rpc_limits::BodyClass` preserves the ordinary 8 MiB class. Explicit
`LargeHexV1` allows finite 40,100,000-byte encoded block/transaction bodies,
including JSON overhead. Metadata and verbose decoded block responses retain
the default ceiling. The class never grants an RPC method. The admin client has
`HttpNodeRpc::with_body_class`; the gateway has `serve_with_body_class`. Existing
constructors retain the default class and all cookie/auth/allowlist and
four-client/deadline protections. `EndpointFile::from_external` exports the
separate `zdn-external-endpoints/v1` schema, with exact request/package/compile,
inventory/host-manifest and gateway service hashes plus a finite body class.
Ordinary endpoint bytes omit this binding and cannot select a larger class.
`validate_gateway_observation` requires the external service hash before a client
dispatches RPC. The connection decoder is wired separately by the coordinator;
the latest combined tests, not this API alone, determine transport coverage.

## Host branch and reused lifecycle algorithms

`host::external::Manifest` is a separate `zdn-external-host/v1` contract, not an
ordinary `HostInstallSpec` with invented consensus fields. Its finite named S3
slots reuse `artifact_delivery::fetch_object` for authenticated streaming
delivery. All source objects must remain in one bucket/account/region; fixed
destination leaves and independent package/selection/executable pins prevent a
directory upload or package-selected execution trust. `validate` rejects
unsupported features/capabilities using `ImageBuildRequirements::new` before
delivery effects. Canonical strict manifest parsing has a 16 MiB total ceiling.

`Manifest::prepare` reads descriptor-relative authenticated host artifacts into
a fresh snapshot, checks package/source slot pins, recompiles, requires the
exact controller result bytes, renders, applies the independent core security
envelope and only then compares exact rendered bytes. It validates the image
record/registry manifest/config with the requirement-aware image APIs. The retained
`PreparedHost` also exposes requirement-aware image-config and Docker-inspection
checks. The explicit external host installer/runtime/update branch selects these
APIs; ordinary host contracts and byte meanings remain unchanged.

Host execution uses `PreparedExternalChain::prepare_isolated`, never the local
same-UID fallback. `host::adapter_sandbox` verifies root-owned, non-writable
`/usr/bin/bash`, `/usr/bin/setpriv`, `/usr/bin/bwrap` and system runtime-library paths.
A fixed noninteractive Bash exec shim closes all inherited non-stdio descriptors
before privilege drop. Paths remain positional arguments, not command text. `setpriv`
drops the real host UID/GID to 65534, clears supplementary groups and all
bounding/inheritable/ambient capabilities, and sets no-new-privileges before
bubblewrap. It must support `--pdeathsig=KILL`, applied after credential changes.
A second fixed trusted exec gate checks the original caller PID after arming
that signal. Caller death before arming refuses before adapter startup; death
after arming kills the launcher. Bubblewrap requires unprivileged namespaces (including network and
PID isolation), die-with-parent, a new session, cleared environment and no
capabilities. It mounts only read-only public execution inputs, read-only system
runtime libraries and a private `/dev`; no host `/etc`, `/proc`, `/run`, home,
node state, RPC cookie or credential path is mounted. Its root is read-only.
Public-only snapshots are made readable by the sandbox UID; private package,
host and wallet files are not copied into that execution directory.

Missing/untrusted tools refuse even delivery admission. Privilege-drop,
namespace, mount or dynamic-loader failures stop before adapter execution, with
no unsandboxed retry. The existing duplex deadline/output and process cleanup
apply; bubblewrap owns its PID namespace on parent death. The existing host
action supervisor/receipts remain required for the outer operation. The coordinator
reported an actual isolated companion compile and two deterministic renders in
this orb, plus an independent C denial probe (UID/GID65534, no groups/capabilities,
no-new-privileges, hidden private host trees, scrubbed environment, read-only root
and a new loopback-only network namespace). This is orb evidence for the sandbox
policy, not deployment-host qualification or execution of the provisioning action.
The later coordinator Rust probe found that non-CLOEXEC descriptors survived the
original setpriv/bubblewrap launch. The corrected actual Rust launcher passes
deliberately inherited file/directory/socket controls; the same-UID negative
control still detects them. A deterministic pre-start caller-crash control
reproduced orphaned adapter startup on the old launcher and verified refusal on
the corrected launcher. Successful completion, cancellation and abrupt caller
death after startup left no running canary descendants, including descendants
that called `setsid` and closed protocol pipes. These are local no-node orb
checks, not host availability protection or deployment-host qualification.
There is no automatic tool installation or an ordinary-deployment dependency.

## Identity-only host execution branch

`host::external::Provisioning` freezes `zdn-external-provisioning/v1` before peer
collection. Its separate `zdn-external-volume/v1` record reuses the existing
exclusive install lock, format intent, volume provenance/zero evidence, mount and
claim state machine through a sealed `VolumeSpec`. Original ordinary volume
record bytes are unchanged. The immutable phase-one identity binds request,
descriptor, native fingerprint, deployment/node and volume, not late-bound peers.

`host::external::identity::Manifest` (`zdn-external-native-provisioning/v1`) binds
that ownership to the fixed eleven authenticated sources and exact controller
identity-only render. Optional `identityOnly:true` in the request is accepted only
for a peerless follower with no reward address and an empty expected ID. Core
independently validates the full config, omitting exactly `expected_node_id` for
this action. Normal runtime render validation still requires the persisted ID.

The hidden root-only provisioning command authenticates its own helper bytes,
checks trusted prerequisites/tools, delivers and freshly recompiles/renders in
the sandbox, validates and inspects the selected pulled image, verifies metadata
firewall rules and prepares the exact volume before native key invocation. Its
bounded supervised Docker command runs only `zakurad --config CONFIG
native-identity --identity-dir ABS`, with network none, UID/GID10001, dropped
capabilities, no-new-privileges and a read-only root. Only the public config file
and persistent identity directory are bind-mounted; state/cookie paths are not.
Container cleanup checks exact name/image/ownership label before selecting an ID.

The public response is strictly bounded, checked against the native fingerprint
and published create-only. Once saved, retries render its expected ID and require
strict load rather than key regeneration. Identity remains separate from state.
A durable attempt fence is published before the first native ensure. If that
attempt is interrupted before its public response is saved, retries refuse to
ensure again: an uncertain first-key result is not authority to regenerate a
missing key. Automatic adoption/repair of that uncertain first response is not
implemented. Retained runtime/bootstrap/producer evidence likewise forbids a new
ensure if its public identity receipt has disappeared; preserve all evidence for
diagnosis rather than deleting the fence to make recovery proceed.
No node service, bootstrap submission, peer connection or producer activation is
performed by this command. The external controller authenticates its saved SSM
output and records it in the persistent cohort inventory before final rendering;
exporting this manifest/script alone does not perform those lifecycle actions.

`PreparedHost::serve_gateway` now selects the finite external class only after
matching its retained exact manifest pin, provisioning identity, fresh native
effective-rule check and external service recipe hash. It retains private-cookie,
identity-file and allowlist protections. The external runtime's gateway unit
selects this branch. Its install action waits for exact authenticated health,
not just a successful `systemctl start` receipt.

`package::PreparedExternalChain::prepare` requires a separate `CoreTrust`
decision (package pin, executable pin and adapter-selection digest). Its private
fields prevent deserialization from masquerading as fresh native compilation.
It exposes `wait_for_rpc`, `verify_rules`, `bootstrap`, `readiness` and `produce`:

- Startup reuses the existing cookie-rotation/401/transport-only retry loop.
- Bootstrap reuses the same pre-mutation native block inspection, dense history,
  uncertain-submission reconciliation and final best-chain verification. The
  external raw bundle is never misinterpreted as the ordinary TAR format.
- Readiness uses the compiled native upgrade/branch schedule and exact complete
  rule equality; ordinary hexadecimal normalization remains unchanged. There is
  no fabricated ordinary manifest or hard-coded external branch schedule.
- Production reuses the existing exclusive lock, durable intent journal,
  readiness checks and uncertain-generation reconciliation. Fingerprint-bound
  producer identity/options are still required. This API does not itself grant
  host production authorization or replace the install/volume fence.

Local controller preparation still uses the explicitly trusted process boundary;
only isolated host preparation selects the fixed sandbox policy. No host service
has been installed or activated during this offline implementation work.

## Final host installation, supervision and retained-state revisions

`host::external::runtime::Manifest` (`zdn-external-runtime/v1`) contains the exact
phase-one `provisioning`, final `chain` host manifest, requirement-aware `image`
record, finite `memoryBytes`, `cpuMillis`, `hostReserveBytes` and optional
`blockIntervalSeconds`. All fields are typed, duplicate/unknown/positional-array
encodings are refused, and canonical compact JSON has a 16 MiB ceiling. The
controller uses `host::runtime::bootstrap::render_external` for authenticated
delivery and `Manifest::render_operation` for fixed subsequent SSM commands.

The hidden host command boundary is:

```text
zdn __external-install --protocol zdn-external-runtime/v1 < manifest.json
zdn __external-runtime --protocol zdn-external-runtime/v1 \
  --manifest /etc/zdn/external-runtime/MANIFEST_SHA256.json OPERATION
zdn __external-update --protocol zdn-external-image-update/v1 < request.json
```

Operations are `prepare`, `run`, `ready`, `observe`, `start-producer`, `produce`,
`stop`, `gateway-install`, `gateway-observe` and `gateway-serve`. The runtime
authenticates its actual helper inode and digest, original provisioning/volume
identity and immutable final installation intent. Only phase-one identity
provisioning may initialize a new disk or ensure a native key. Final install and
restart require the retained public identity and exact `expected_node_id`; node
startup itself strictly loads and matches the private key. Missing/corrupt keys
are never regenerated by this branch.

Final runtime preparation authenticates the helper through its trusted directory
descriptor in bounded chunks, checking its full size/hash and ELF prefix without
copying it into the temporary adapter-input snapshot. The other ten artifacts
retain their existing snapshot checks. This avoids a helper-sized buffer and
copy; it does not establish a whole-operation memory bound or qualify any service
memory limit. Native-identity preparation and service policies are unchanged.

Final install freshly recompiles/renders under isolation, verifies pulled image
configuration, applies the existing metadata firewall and volume preparation
algorithm with formatting disabled, and publishes root-owned read-only config,
content-addressed helper/manifest and node/producer/gateway units. It releases
the original installation lock before activation children acquire that lock.
The node and producer share the ordinary supervisor template and closed Docker
launch/inspection/cleanup algorithms, not a parallel launcher. Gateway startup
is read-only and does not take the installation lock, call cloud tools or write
host receipts. The external gateway's trusted wrapper needs CAP_SETUID,
CAP_SETGID and CAP_SETPCAP to drop all privileges before its isolated companion;
the companion inherits none. AF_UNIX and AF_NETLINK are permitted for sandbox
setup, alongside the ordinary gateway socket families. Bubblewrap needs
NETLINK_ROUTE to configure loopback inside its isolated network namespace;
omitting AF_NETLINK makes startup fail before the adapter executes. This does
not add host CAP_NET_ADMIN or CAP_SYS_ADMIN, relax the namespace isolation, or
change the ordinary gateway unit. The original public package's compile/render
preflight has passed locally under the generated systemd restrictions after
this correction; a complete cloud gateway/payment journey remains unqualified.

`ready` runs the seed bootstrap only when its durable identity-bound completion
is absent and the local producer service is demonstrably stopped. Retained-state
restarts skip seed submission but still check fresh native rules/history and
container isolation. The authenticated controller must keep the whole cohort
stopped during first history loading and collect all readiness gates before
invoking node-1 `start-producer`. That action creates exact durable authorization
only after local readiness; actual production uses the existing exclusive
lock/intent/pending-generation journal and reconciler. Startup observations
check service MainPID, journal owner/lock, cadence and healthy phase.

`runtime::update::Request` (`zdn-external-image-update/v1`) binds `original`,
UUIDv4 `updateId`, `expectedImage`, optional `expectedUpdateId` and `target`.
Only image selection and its three public proofs may change. Key/peer inventory,
runtime helper, public chain inputs, configuration, paths, resources and producer
authorization stay exact. The existing revision journal algorithm is shared
through typed hooks, with ordinary aliases preserving old serialized bytes.
External receipts use `external-updates`, the same forward-only
staging/stopping/activating/ready/done phases and durable hold-before-stop rule.
Target artifacts are isolated per update UUID. Startup/producer gates consume
that journal; readiness and retained authorization precede maintenance release.
Failed release re-holds maintenance and stops the producer. Exact saved update
requests resume forward; neither rollback nor bootstrap replay is invented.
After an update, callers continue invoking the original immutable manifest's
`render_operation` command. The revision journal selects its active target;
returned runtime observations and gateway service identity describe that target,
not the old image. Do not substitute the target's manifest path for the saved
original installation command.

Ready responses contain `observation` (`zdn-external-runtime-observation/v1`,
runtime/request/inventory pins plus deployment/node/native identity) and native
`readiness`; start-producer additionally returns `producer`. Controllers can use
`Manifest::validate_ready_observation` after authenticating SSM request/output.
Gateway actions return the existing gateway observation with the external
service hash. Stop and structural manifest/volume inspection do not load or run
the companion, even if it is absent or unsupported.

These are implementation paths, not claims of successful host installation,
systemd activation, live bootstrap, cloud recovery or producer qualification.

## Precise remaining gates

- Qualify prerequisites and the real action supervision/cleanup on deployment
  hosts. Orb sandbox execution is available evidence, not AWS host qualification.
- Run the separately approved TPQ bootstrap, peer synchronization, funding,
  payments, retained-key restart, update and restored-wallet journey. Offline
  transport and host supervisor regressions do not qualify live activation.
- Retain current candidate-specific native-platform results; historical ordinary
  releases and an available runner are not evidence for this implementation.
- Keep combined offline checks current after controller/source/handoff changes.
  This offline implementation did not create external resources.

## Offline regression commands

Run these ordinary offline checks serially with other substantial builds. A
command list is not a passing result; record actual outcomes for each candidate:

```sh
cargo fmt --all -- --check
cargo test --locked --test public_chain_adapter --test external_chain_contract \
  --test external_provisioning --test endpoints --test chain_rpc --test client_gateway_runtime
cargo test --locked --test host_revision
cargo test --locked --test cli native_runtime_protocol_is_explicit
cargo test --locked --lib rpc_limits
cargo test --locked --lib host::adapter_sandbox
cargo test --locked --test cli explicit_external_config
cargo test --locked --test external_controller --test handoff --test removal
cargo clippy --all-targets --locked -- -D warnings
```

Full ordinary ZDN regression remains required for configuration/transport changes.
There was no live node, container/proof/cloud/performance workload, release asset,
publication or commit. Offline tests do not credit a live ZDN beta case or qualify
TPQ payment/restore behavior.
