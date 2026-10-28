# Local source capture

Source capture creates `source.tar` and `receipt.json` in a new local directory.
It does not commit, push, fetch, build, upload, or contact AWS. Git must be
installed, and the selected checkout must have at least one commit.

The output directory must be outside the selected Git checkout. Its parent must
already exist. Select a new output directory for each snapshot. A completed
snapshot cannot be replaced by another capture.

## Capture from a configuration

For the preview's reviewed node source, download and verify the public source
archive and accompanying source map using the
[release setup guide](preview-start.md#1-select-and-verify-a-profile). A private
research checkout is not required. Use the revision recorded for that public
source, not a historical revision mentioned in attribution notes.

Run from a separate working directory. Set `NODE_SOURCE` to the absolute Git
root and `NODE_REV` to the exact reviewed commit from the release source map:

```sh
zdn init --config devnet.yaml --source "$NODE_SOURCE" --revision "$NODE_REV" \
  --nodes 1 --dockerfile node/zakura/docker/Dockerfile --build-context .
zdn snapshot --config devnet.yaml --output "$PWD/source-snapshot"
```

`init` writes configuration only. `snapshot` reads `node.source.path` and
`node.source.revision` from that file; it has no `--revision` flag. The recipe
above is for the preview archive. Select the appropriate Dockerfile for any
other reviewed checkout.

For working-file capture instead, create a separate configuration without
`--revision`. Include an untracked file only when it belongs in the build:

```sh
zdn init --config working.yaml --source "$NODE_SOURCE" --nodes 1 \
  --dockerfile node/zakura/docker/Dockerfile --build-context .
zdn snapshot --config working.yaml --output "$PWD/working-snapshot" \
  --include path/to/new-file.rs
```

Replace the include path with an actual source-relative file, or omit
`--include`. It cannot be combined with revision capture. Both output directories
must be new and outside `NODE_SOURCE`. Inspect each `receipt.json` before using
its `source.tar` as a build input.

## Working files

The default mode selects files from the Git index and copies their current
working bytes. It includes staged additions and edits made after staging.
Tracked deletions remain deleted. A staged deletion that has been recreated as
an untracked file remains omitted unless the user includes that file explicitly.
Git worktrees and detached HEAD checkouts are supported. Select the Git worktree
root as the source. A nested source path produces an error, so capture cannot
silently expand a subdirectory to a whole repository. Sparse or skip-worktree
omissions produce an error; restore the full checkout before capture.

An explicit include selects one exact, checkout-relative file. Repeat the include
option for several files. Directories, absolute paths, and paths containing `..`
are rejected. Ignored files can be included explicitly if they pass the exclusion
rules below. Ordinary untracked files that were not selected are listed in the
receipt. Git-ignored files are not added to that omitted-untracked list; Cargo
validation still checks implicit source paths, including entries under `src/bin`.

The receipt records HEAD, branch, dirty status, deletions, omitted untracked paths,
excluded paths, and each captured file's path, kind, mode, size, and SHA-256 hash.
Symlink hashes describe their target text. Capture compares the index and selected
raw working bytes with HEAD. It does not run `git status`, clean/smudge/process filters,
or repository filesystem-monitor commands. Every Git call disables fsmonitor and
hooks. Byte comparisons also detect hidden tracked edits and explicitly included
ignored files. Filtered or line-normalized working bytes can therefore make a
snapshot dirty even when Git would report a clean checkout.

## Exact revisions

Revision mode resolves an input revision to one commit and reads that commit's
objects. Current working edits do not enter the snapshot. The receipt records
the resolved commit, with no branch label and no dirty flag. Includes cannot be
combined with this mode.

Git `export-ignore` and `export-subst` rules do not remove or rewrite source files.
License files keep their original bytes. Required objects must already exist
locally; automatic fetches for partial clones are disabled. Git replacement refs
are ignored for all capture reads, including commit, tree, and blob replacements.
The recorded commit therefore identifies the original Git objects.

Revision capture keeps exact Git path names, including names that differ only
by case. Temporary file names do not use source path names, so a case-insensitive
local filesystem cannot merge these files. The archive retains each path's own
bytes and mode without checking out the selected tree.

## Source boundaries

Both modes exclude known Git internals, local state, credentials, wallet data,
and generated output, even when these files are tracked. The current rules cover:

- Directory components `.git`, `.context`, `.aws`, `.ssh`, `.gnupg`, `.zdn`,
  `.pulumi`, `.zcash`, `.zakura`, `.zebra`, `.lightwalletd`, `target`, `node_modules`,
  `__pycache__`, `.venv`, and `venv`.
- Credential files named `credentials`, `credentials.json`, `credentials.toml`,
  or `credentials.yaml`; `.env` and `.env.*` except example, sample, and template
  files; private key files ending in `.pem`, `.key`, `.p12`, or `.pfx`.
- `wallet.dat`, `wallet.db`, `wallet.sqlite`, `wallet.sqlite3`, `wallet.keys`,
  `wallet.seed`, `mnemonic`, `id_rsa`, and `id_ed25519`.
- Generated Pulumi stack files named `Pulumi.*.yaml`, `Pulumi.*.yml`, or
  `Pulumi.*.json`.

These are path rules, not a general secret scanner. Review the selected source
before a later upload step. Never store real wallet secrets in source files.

Symlinks must be relative, stay inside the checkout, and resolve to captured
files or directories. Dangling links, cycles, directory symlink substitutions,
and links to omitted files fail capture. Paths and link targets must use UTF-8.

Git submodules and Git LFS files are rejected. Hydrated working LFS
files and unresolved LFS pointers both produce an explicit error. Capture does
not run Git LFS or initialize submodules.

Cargo manifests and Cargo configuration files are parsed as TOML. Declared path
dependencies, patches, replacements, workspace dependencies, target dependencies,
and configuration path overrides must stay inside the snapshot. Their required
`Cargo.toml` files must be captured. External workspace members are rejected.
Capture does not resolve external dependencies by copying a parent directory.

Directory source replacements must resolve to captured directories. Explicit
build scripts and library/binary entry paths must resolve to captured files.
Existing default entrypoints
such as `build.rs`, `src/lib.rs`, `src/main.rs`, and inferred `src/bin` targets must
also be captured. An omitted or ignored default entrypoint stops working-source
capture; revision capture consults only the selected Git tree. Disabled automatic
targets and `build = false` keep their Cargo meaning. These checks do not execute
Cargo or inspect arbitrary files that a build script or Rust macro might read.

Workspace member globs are expanded over captured paths. Patterns such as
`crates/*/core`, `crates/[ab]/core`, and `crates/**/core` are supported. A `*` or
`?` cannot cross a directory separator. Each selected member directory must have
a captured `Cargo.toml`; an omitted member manifest fails before publication.
Stage the missing files or include them explicitly, then capture again. A glob
with no matches also fails. Existing plain files matched by a glob are ignored.

Workspace exclusions use Cargo's literal directory-prefix behavior. An explicitly
named member takes precedence over an exclusion; a glob match does not. Captured
internal directory symlinks can be used in member paths. Expansion checks link
targets before processing `..`, rejects recursive link cycles, and limits each
recursive wildcard to 64 directories. A pattern has limits of 100,000 expansion
steps and 256 nested matching steps.
These checks follow the [Cargo workspace member rules](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-members-and-exclude-fields)
without reading omitted working files or running Cargo during capture.

This check does not replace Cargo's build validation or inspect arbitrary build
script inputs. Registry and Git dependencies remain subject to the later locked
build recipe.

## Stable archives and failures

Files are ordered by path. Tar ownership and timestamps are fixed. Executable
file modes and symlink targets are retained. Equal selected source bytes, modes,
and paths produce equal uncompressed archives, independent of file timestamps.
The receipt includes the archive size and SHA-256 hash.
Archive creation also checks that each regular file's bytes match its recorded
size and hash. A mismatch stops capture before the snapshot is published.
The complete archive and receipt are flushed and synced before publication.

Capture records source metadata before copying. It checks Git state, file
metadata, and file bytes again before publication. An observed change fails the
capture.

Incomplete files stay in a private temporary directory. After validation, capture
moves the complete snapshot directory into place under a local file lock. A
busy lock fails immediately. A normal error removes temporary files. A killed
process can leave an unpublished
`.zdn-capture-*` directory beside the output; it is never used as a completed
snapshot. A retry uses the original completed snapshot or chooses a new output
directory. Source capture does not turn a mutable checkout into a filesystem
snapshot and does not defend against a malicious process changing files to evade
all checks.

## Fast checks

Run `cargo test --locked --test source_capture` from the zdn workspace. The suite
uses small temporary Git repositories, local archives, and deterministic mutation
hooks. It checks bytes, hashes, modes, deletion and rename behavior, dirty files,
worktrees, exact revisions, case collisions and replacement refs, excluded files,
dependencies, workspace patterns and missing manifests, links, concurrent
publication, failed captures, staging corruption, and retries. It needs no
Docker, AWS, nodes, or downloaded fixtures.
