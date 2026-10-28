# Zakura image inputs

Advanced reference for image publishers and contributors, not an installation
procedure. First-time operators should follow the [preview setup guide](preview-start.md);
the source-build workflow produces and verifies these image records for them.

The node image is a Linux x86-64 image pinned by its **single-platform child
manifest digest**. A tag, a release name, and a multi-platform index digest do
not satisfy this contract. Keep three files with the image: its record, the
exact registry manifest bytes, and the exact registry configuration bytes.

Supply an image that implements the required diagnostics and the runtime paths below.
The record declares those capabilities. Bootstrap and readiness must check
the running node before it can join a devnet.

## Record

Use `zdn-zakura-image/v1alpha1`. All fields are required. Unknown fields fail
validation. This example shows the shape; its hashes are placeholders:

```json
{
  "apiVersion": "zdn-zakura-image/v1alpha1",
  "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/example/zakura@sha256:CHILD_MANIFEST_SHA256",
  "configDigest": "sha256:CONFIGURATION_SHA256",
  "platform": "linux/amd64",
  "provenance": {
    "kind": "source",
    "revision": "FULL_GIT_REVISION",
    "snapshotSha256": "SOURCE_SNAPSHOT_SHA256"
  },
  "capabilities": {
    "ruleset": "zakura-configured-testnet/v1",
    "chainRulesApi": "zakura-chain-rules/v1",
    "blockInspectionApi": "zakura-block-inspection/v1",
    "runtimeAdapter": "zakura-runtime-toml/v1alpha1",
    "cookieAuth": true,
    "blockSubmission": true,
    "generateRpc": true
  },
  "binaryPath": "/usr/local/bin/zakurad",
  "environmentLauncher": "/usr/bin/env"
}
```

For a release, replace `provenance` with
`{"kind":"release","revision":"FULL_GIT_REVISION","version":"EXACT_VERSION"}`.
Full revisions use 40 or 64 lowercase hexadecimal characters. SHA-256 values
use 64 lowercase hexadecimal characters. A source snapshot identifies the
saved build input, including local changes. A release record still needs the
source revision. Metadata does not authenticate the builder or prove that the
image was built from that source.

The reference must include an explicit registry hostname and repository. It
must omit tags, credentials, URL schemes, whitespace, and shell syntax. The
core image contract supports registry hostnames with an optional port. An AWS
deployment can impose a narrower repository policy.

## Checks before allocation and start

1. Validate the record. The adapter requires exactly the capability versions
   above and the two fixed executable paths.
2. Hash the saved manifest **without reformatting it**. It must match the image
   digest. Accept OCI image manifests or Docker schema-2 image manifests.
   Reject indexes, manifest lists, artifact manifests, and foreign layers.
3. Hash the saved configuration bytes. Their length and SHA-256 must match the
   manifest descriptor. Read Linux/amd64, filesystem layer identities, and
   runtime defaults from those bytes. Reject unsupported platform or startup
   defaults before creating hosts.
4. On each host, pull the immutable reference and inspect that exact image.
   The trusted Docker daemon's image ID must match `configDigest`. Its repository
   digest must match the complete reference, including the repository. Check
   Linux/amd64 and runtime defaults again.
5. Start with the explicit launch settings below. Use authenticated
   [bootstrap and readiness](bootstrap-readiness.md) to check parsed rules,
   stored history, and a current template for a producer.

The manifest has at most 128 layers. Saved records, manifests, configuration
blobs, and Docker inspection output have size limits. The Docker daemon still
checks pulled layer content. The local checks do not extract or run an image.

`image::validate_manifest_bytes` returns a receipt bound to the complete record.
`image::validate_config_bytes` and `image::validate_docker_inspect` require that
receipt. The receipt cannot be deserialized as a substitute for checking the
manifest. The Docker inspection function expects the unmodified JSON array
for exactly one image from `docker image inspect`.

## Launch settings

The launcher overrides image entrypoint, command, user, working directory,
stop signal, and healthcheck. The required process arguments start with:

```text
/usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/nonexistent /usr/local/bin/zakurad --config CONFIG_PATH start
```

Use UID/GID `10001:10001`, working directory `/`, stop signal `SIGINT`, and
disable image healthchecks. The host prepares private writable state and cookie
directories for that UID. The node binary path follows the inspected Zakura
Dockerfile. Overriding its entrypoint also bypasses that script's privilege and
directory setup, so the host must do that work.

`env -i` clears inherited image variables before Zakura starts. Image environment
checks run first because variables such as `LD_PRELOAD` can affect the environment
launcher itself. Only the safe PATH, HOME, UID, GID, USER, and FEATURES values
used by the inspected runtime image are accepted. Unknown, duplicate, malformed,
or unsafe variables fail. Image-declared volumes and build triggers also fail.
Image command strings and labels are never copied into host shell commands.

The image inspection report keeps `capabilitiesObserved: false`,
`qualification: pending`, and `launchReady: false`. `requiredLaunch` lists
requirements; it does not claim they have been applied. A publisher label, an
open RPC port, or a matching version string cannot qualify a chain recipe,
lightwalletd, or wallet payments. A complete launch must also enforce the
[runtime configuration](runtime-config.md) and deployment ownership rules.

## Tests and format references

Run `cargo test --locked --test image`. These tests use saved JSON fixtures and
cover immutable identities, manifest/config binding, wrong platforms,
multi-platform references, unsafe defaults, malformed inputs, and receipt reuse.
They require no Docker, registry, AWS identity, or node process.

The data mapping follows the [OCI image manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md)
and [image configuration](https://github.com/opencontainers/image-spec/blob/main/config.md)
formats and [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/).
