# Digest-pinned deployment packages

A deployment package is a local JSON manifest, not a tar archive, executable
installer, release catalog or cross-machine deployment handoff. It names one
versioned artifact set and the location of each member. Both completed source
builds and release images use the same contract.

```sh
zdn package verify --manifest /path/to/package.json --sha256 "$PACKAGE_SHA256"
zdn devnet render --package /path/to/package.json --package-sha256 "$PACKAGE_SHA256" \
  --reward-address "$REWARD_ADDRESS" --ami-id "$AMI_ID" --availability-zone "$ZONE"
```

Obtain the lowercase SHA-256 of the **raw manifest bytes** through a trusted
channel. Reformatting the JSON changes that pin. `package verify` only resolves
artifacts and reports local consistency; it does not execute the helper, pull
container layers, authenticate a publisher or establish live readiness.

`devnet up` accepts the same package flags and requires `--yes` for cloud changes.
The existing configuration, team access, ECR namespace and pre-allocation image
checks still apply. Use a configuration pinned to the package's exact node image,
not a source-path configuration. A completed source-build package can carry its
build contract without rebuilding or recapturing a checkout. Lightwallet selection
must exactly match `services.lightwallet`; wallet and faucet remain unsupported.

## Manifest contract

The public Rust types are `package::Package` and `artifact_set::ArtifactSet`.
Fields use camelCase and unknown fields are rejected. The top-level shape is:

```text
{
  "apiVersion": "zdn-deployment-package/v1alpha1",
  "artifactSet": { ...complete ArtifactSet below... },
  "sources": {
    "manifest.json": { "kind": "file", "path": "chain/manifest.json" },
    "chain.tar": { "kind": "https", "url": "https://example.org/chain.tar" },
    ...one location per artifact...
  }
}
```

This is a structural example, not a usable package. A complete `artifactSet` has:

| Field | Required value or meaning |
| --- | --- |
| `apiVersion` | `zdn-artifact-set/v1alpha1` |
| `platform` | `linux/amd64` |
| `consensusFingerprint` | Normalized consensus manifest fingerprint, 64 lowercase hex characters |
| `nodeImage` | Complete [image record](image-contract.md), including digest, platform, capabilities and provenance |
| `build` | Optional completed [BuildContract](builds.md); source hash/size, revision, recipe, platform and required capabilities must bind to `nodeImage` |
| `lightwalletImage` | Optional complete [lightwallet image record](lightwallet-service.md) |
| `compatibility` | `chainBundleApi`, `runtimeAdapter`, `helperVersion`, `lightwalletProtocol` matching the current CLI contracts; protocol is null when lightwallet is disabled |
| `provenance` | Exactly `chain`, `node`, `helper`, plus `lightwallet` when enabled |
| `artifacts` | Exact fixed inventory below; each value is `{ "sha256": "<64 lowercase hex>", "bytes": <positive raw length> }` |

Each provenance entry contains `sourceUrl` (HTTPS without credentials), `revision`
(full lowercase 40- or 64-character Git revision), and a nonempty `license`
declaration. Node and lightwallet revisions must match their image records.
These are publisher declarations, not signed attestations or a license audit.
`helperVersion` must match the CLI package version for package resolution,
render/up retries and image updates; header validation cannot prove that the
helper actually implements that version. A helper-version mismatch alone does
not prevent loading, inspecting, saving or destroying an existing deployment.
Those operations preserve its original contract and fingerprint, rather than
silently changing its helper declaration. Other schema checks still apply.

The six mandatory artifacts are `manifest.json`, `chain.tar`, `image.json`,
`image-manifest.json`, `image-config.json`, and `zdn`. Lightwallet adds
`lightwallet-image.json`, `lightwallet-image-manifest.json`, and
`lightwallet-image-config.json`. No extra artifacts or locations are accepted.
Image layers remain in the registry; this is not an air-gapped image export.

## Resolution, overrides and recovery

The raw manifest is bounded to 2 MiB and hash-checked before decoding or fetching.
File locations are relative to its directory: absolute paths, traversal and symlink
components are rejected. HTTPS locations cannot contain credentials or fragments.
Downloads use the existing bounded HTTPS transport; tests explicitly inject a
loopback transport. Each member must match its declared size/hash and existing
artifact-size limits. The resolver checks chain-bundle consistency, OCI child
manifest/config digests and platform, image identity/capabilities, helper ELF
header and compatibility declarations before returning disposable private storage.
On Unix the directory is created as `0700` and artifact files as `0600`, regardless
of a permissive umask; permissions are not tightened after copying. It does not
execute any artifact. Failed or dropped resolutions remove that storage.

Expert flags such as `--host-helper`, `--manifest` and `--image-record` remain
available. With a package, each supplied override must match the package's same
size/hash pin and semantic checks; overrides are not a way to replace a component.
Without a package, existing expert/source-build workflows are unchanged.

Successful staging copies artifacts into the existing immutable deployment
directory and saves the full artifact-set contract in the cluster request.
`devnet render` reports `artifactSetSha256` for package deployments. Unchanged
render/up retries omit package and artifact flags and verify saved bytes, even
after the originals disappear. Metadata changes, including license/provenance,
cannot replace the saved set. This does not add transfer/attach of a deployment to
another machine. [Signed release catalogs](releases.md) provide a separate
explicit-key authentication and exact selection layer, reusing this same package
contract. `package export --manifest PATH --sha256 PIN --output NEW_DIRECTORY`
prepares a relocatable data-only snapshot on Linux; no existing output is replaced.
Export itself does not authenticate a publisher or publish externally.

For contributor checks, see the [test coverage notes](testing.md#subsystem-coverage-notes).
