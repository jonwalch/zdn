# Prerequisites and managed tools

`zdn doctor` checks the local versions of Git, AWS CLI v2 >= 2.37.4, and the AWS Session
Manager plugin. It checks the managed tool receipt when given a managed directory.
It does not call AWS, check permissions, sign in, download files, or change resources.
A passing local check does not establish a working AWS identity.
Version probes bound the direct subprocess. They do not provide process-tree
cancellation for arbitrary wrapper scripts. The [Pulumi adapter](pulumi.md)
provides process-group cleanup for deployment commands.

Install the three prerequisites with their upstream installers. Then use
`zdn deps install` to download the pinned Pulumi tools. This command does not need
AWS credentials, Docker, a local Rust compiler, or a Pulumi Cloud account.
The [AWS foundation](infrastructure.md) uses these tools for one private test host.

## Pinned catalog

[The bundled catalog](../data/managed-tools-v1.json) contains separate archives and
SHA256 pins for macOS and Linux, each on x86-64 and ARM64. It selects:

| Tool | Version | Upstream release |
| --- | --- | --- |
| Pulumi CLI | 3.268.0 | [CLI release](https://github.com/pulumi/pulumi/releases/tag/v3.268.0) |
| Pulumi YAML runtime | 1.38.10 | [YAML release](https://github.com/pulumi/pulumi-yaml/releases/tag/v1.38.10) |
| Pulumi AWS provider | 7.50.0 | [AWS release](https://github.com/pulumi/pulumi-aws/releases/tag/v7.50.0) |

The SHA256 values were read from the official GitHub release asset metadata on
2026-10-14. CLI and YAML values were also checked against each publisher's SHA256
checksum file. The AWS release's legacy checksum file uses SHA1; zdn instead pins
the SHA256 asset digests reported by GitHub. Downloads use the committed catalog;
the installer never accepts a new checksum from the download server at runtime.
This is checksum verification against reviewed pins, not signature verification.

The catalog also fixes compressed size limits, unpacked size limits, required
files, and allowed bundled executables. Archive layouts were checked against the
upstream release scripts. Their complete archive contents and executable behavior
still need packaging checks on each supported platform. Pins alone do not
qualify the Pulumi/provider combination for an AWS deployment.

## Installation and recovery

The installer downloads each archive through HTTPS. An archive must match its
SHA256 pin before any file is extracted. It rejects traversal, links, special
files, privileged modes, duplicate entries, unexpected executables, missing files,
truncated data, and size-limit violations. It installs only the required binaries.
Unneeded runtimes in the CLI distribution do not become runnable tools.

One local filesystem lock excludes concurrent installers. A second installer
returns a retry message. Downloads have a five-minute deadline per archive,
including redirects, plus connect/read timeouts. DNS lookup waits at most 15
seconds and shares the archive deadline. A timed-out OS DNS lookup can finish
later in an isolated worker; that worker cannot write archives or change installer
state. No shell command constructs the download or extraction operation.

All tools first go into a private temporary staging directory. Files and their
receipt are synced before the complete directory is renamed into `versions/`.
An atomic replacement of `active.json` is the only activation point. A checksum
failure, failed download, or process interruption preserves the previously active
installation. A later install removes abandoned staging directories under the
same lock. Older complete versions remain available; this stage adds no automatic
garbage collection.

The receipt names the catalog digest, platform, archive pins, installed file
hashes, and paths. Repeating the same install checks those hashes and reuses the
version without downloading. Modified files or inconsistent receipts cause an
error. Special files such as FIFOs are rejected before opening them. The tool
does not silently overwrite an altered installation. To repair
such an installation, move the reported version directory aside and rerun the
installer. Keep the managed directory writable only by its owning user. Receipt
hashes detect accidental changes; they do not protect against an attacker who can
rewrite both a binary and its receipt.

Each installed version contains:

```text
bin/pulumi
bin/pulumi-language-yaml
pulumi-home/plugins/resource-aws-v7.50.0/pulumi-resource-aws
receipt.json
```

The [Pulumi process adapter](pulumi.md) uses this exact CLI and YAML runtime,
explicitly selects the pinned provider, and sets the matching plugin location.
It does not depend on whichever Pulumi version happens to be in the user's PATH.
This installer does not log in, create Pulumi projects, or initialize state.

## Fast checks

Run `cargo test --locked --test dependencies`. The suite uses generated archives,
fake executables, temporary directories, child processes, and a numeric loopback
HTTP server. It does not require an installed AWS CLI, Pulumi, Docker, credentials,
or an external download. The production downloader refuses plain HTTP; its
explicit component-test constructor allows HTTP only on numeric loopback hosts.

The checks cover version rejection, missing prerequisites, literal subprocess
arguments, timeout handling, SHA256 failure, partial HTTP responses, unsafe
archives, changed installed files, FIFO rejection, concurrent installation, and a child installer
killed during staging. The next install must preserve the prior active version
and recover without trusting the partial download.

`cargo test --locked --lib dependencies::resolver_tests` checks the DNS deadline
with local injected results and a blocked lookup. It does not call an OS resolver
or use the network.

## Local journal catalog dependency

The explicit [wallet journal migration](wallet.md#explicit-indexed-journal-migration-and-local-inventory)
uses `rusqlite = 0.37.0` (MIT, <https://github.com/rusqlite/rusqlite>) with
`bundled` SQLite and `limits`, locked through Cargo.lock to `libsqlite3-sys 0.35.0` and SQLite
3.50.2 (public domain, <https://www.sqlite.org/copyright.html>). Upstream source
and license attribution remain in the crates; no source is copied into ZDN.
This adds a native C compilation step, not a system SQLite runtime prerequisite.
Transitive versions/checksums are recorded in Cargo.lock. No wallet, crypto, node,
or backend database dependency is introduced.

The concrete access requirements are immutable operation-ID uniqueness across
unbounded retained cancellation tombstones, exact-ID lookup and bounded keyset
inventory, plus atomic updates of record and active/cancelled classification.
SQLite's established indexed transactional store avoids inventing a multi-file
B-tree, deletion log or ever-growing in-memory catalog. DELETE rollback journaling
with synchronous EXTRA is used; the network-wide file lock remains authoritative
for coordination. This format still streams lifetime validation and does not enable
signed-settlement archival or reservation release.
