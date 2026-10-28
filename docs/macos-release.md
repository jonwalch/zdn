# Maintainer workflow: signed and notarized Mac releases

Use this runbook to prepare a **new** Mac release with normal macOS security
protections intact. It is not an installation workaround for Preview 2.
The current browser-downloaded Preview 2 controller and wallet fail to launch;
see [platform status](preview.md#platform-and-trust-limits).

**Status: prepared, not executed or qualified.** Signing, timestamp requests,
Apple submission, installation and publication are separate authorized actions.
Do not run those steps merely because you were asked to review this document.
No signing credentials belong in this repository, an artifact, logs or chat.

## 1. Apple setup (account owner)

1. Have an active **Apple Developer Program** membership and access to its Team
   ID. Choose the individual or organization identity you want customers to see
   as the publisher. This is distribution outside the Mac App Store; it does not
   require an App Store listing.
2. The **Account Holder** creates two certificates in Apple's
   [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources):
   **Developer ID Application** for executable signing, and **Developer ID
   Installer** for `.pkg` signing. These are not Apple Development, Mac App
   Distribution or self-signed certificates.
3. Generate each certificate signing request on the trusted signing Mac using
   Keychain Access. Download/install the issued certificates there. Each must
   have its matching private key in that Mac's keychain; a `.cer` alone cannot
   sign. Keep an encrypted recovery copy under the owner's control, outside Git.
   Do not export keys to build sandboxes or make them broadly accessible to agents.
4. Install current Xcode and its command-line tools, finish its normal license
   and first-launch setup, and confirm the selected tools provide `codesign`,
   `pkgbuild`, `notarytool` and `stapler`. Do not change system-wide tool selection
   or keychain permissions automatically on a shared machine.
5. Configure notarization credentials locally. For the initial owner-operated
   path, use an Apple Account with access to the team and an app-specific password
   entered at the interactive prompt below. A named keychain profile stores it;
   the profile name is not the password. App Store Connect API-key authentication
   is an alternative for a later reviewed automation setup, not a prerequisite.

Read-only checks on the signing Mac:

```sh
xcode-select -p
xcrun --find notarytool
xcrun --find stapler
security find-identity -v -p codesigning
security find-identity -v
```

Require an accessible `Developer ID Application: … (TEAMID)` identity and a
`Developer ID Installer: … (TEAMID)` identity with their private keys. The
codesigning-policy query alone is not an installer-identity inventory. Use
Keychain Access if the listing is ambiguous; do not create replacement
certificates or widen keychain ACLs merely to make a check pass.

After replacing the non-secret placeholders, the account owner runs this locally
and enters the app-specific password only at Apple's prompt:

```sh
xcrun notarytool store-credentials zdn-notary \
  --apple-id YOUR_APPLE_ACCOUNT --team-id YOUR_TEAM_ID
```

This writes credentials to the local keychain and validates them with Apple.
Do not add `--password` to a logged command, enable shell tracing or paste the
password here. Protect the keychain and approve only the intended signing-tool
access. Certificate/keychain setup and notarization are not hosted-CI gates.

## 2. Freeze verified native inputs

Complete ordinary checks and preserve the exact native build/source/toolchain
receipts for **both** ZDN and the separately built Ironwood wallet. This runbook
does not build nodes, generate proofs, run AWS tests or qualify wallet payments.
Do not silently use whichever executable happens to be in a shared target directory.

Run in a dedicated release shell on the Mac. Replace every placeholder; choose
a new release label and a monotonically increasing numeric installer version.
The installer version is independent of the CLI's internal `0.1.0` label.

```sh
set -eu
umask 077
RELEASE=REPLACE_WITH_NEW_RELEASE_LABEL
PACKAGE_VERSION=REPLACE_WITH_NUMERIC_INSTALLER_VERSION
TEAM_ID=REPLACE_WITH_APPLE_TEAM_ID
APP_IDENTITY='Developer ID Application: REPLACE_WITH_PUBLISHER (TEAMID)'
INSTALLER_IDENTITY='Developer ID Installer: REPLACE_WITH_PUBLISHER (TEAMID)'
NOTARY_PROFILE=zdn-notary
ZDN_INPUT=/absolute/path/to/reviewed/native/zdn
WALLET_INPUT=/absolute/path/to/reviewed/native/ironwood-wallet
ZDN_INPUT_SHA256=REPLACE_WITH_REVIEWED_BUILD_HASH
WALLET_INPUT_SHA256=REPLACE_WITH_REVIEWED_BUILD_HASH

test "$(uname -s)/$(uname -m)" = Darwin/arm64
test -f "$ZDN_INPUT" && test ! -L "$ZDN_INPUT"
test -f "$WALLET_INPUT" && test ! -L "$WALLET_INPUT"
test "$(shasum -a 256 "$ZDN_INPUT" | awk '{print $1}')" = "$ZDN_INPUT_SHA256"
test "$(shasum -a 256 "$WALLET_INPUT" | awk '{print $1}')" = "$WALLET_INPUT_SHA256"
file "$ZDN_INPUT" "$WALLET_INPUT"
STAGE=$(mktemp -d /private/tmp/zdn-sign-XXXXXXXX)
test "$(cd "$STAGE" && pwd -P)" = "$STAGE"
mkdir "$STAGE/zdn" "$STAGE/wallet" "$STAGE/output"
cp "$ZDN_INPUT" "$STAGE/zdn/zdn"
cp "$WALLET_INPUT" "$STAGE/wallet/ironwood-wallet"
chmod 755 "$STAGE/zdn/zdn" "$STAGE/wallet/ironwood-wallet"
```

Require native Mach-O arm64 inputs. Intel or universal distributions require their
own reviewed builds and qualification; do not infer them from this path.
Keep the stage private and outside Git. Hash comparison establishes correspondence
to reviewed build records, not trust in an arbitrary downloaded file.

## 3. Sign the staged copies (authorization required)

This replaces only the copies' linker-generated ad-hoc signatures. It must never
modify the reviewed inputs, retained failure evidence or published Preview 2.
Apple's timestamp service is contacted. Use stable reverse-DNS code identifiers;
these examples do not require an App Store listing or a provisioning profile.

```sh
codesign --force --sign "$APP_IDENTITY" --options runtime --timestamp \
  --identifier io.github.jonwalch.zdn "$STAGE/zdn/zdn"
codesign --force --sign "$APP_IDENTITY" --options runtime --timestamp \
  --identifier io.github.jonwalch.ironwood-wallet "$STAGE/wallet/ironwood-wallet"

for binary in "$STAGE/zdn/zdn" "$STAGE/wallet/ironwood-wallet"; do
  codesign --verify --strict --verbose=4 "$binary"
  codesign --display --verbose=4 "$binary"
  codesign --display --entitlements - "$binary"
done
```

Inspect and retain the results. Require the intended Developer ID Application
authority, **exact `TeamIdentifier` matching `TEAM_ID`**, hardened runtime and
secure timestamp. No permissive entitlements are intended: do not add
`get-task-allow`, JIT, unsigned executable memory or disabled library-validation
exceptions to bypass a failure. Stop and diagnose any unexpected requirement.
An integrity check alone is not a notarization or Gatekeeper pass.

## 4. Package, notarize and staple (authorization required)

Create separate script-free installer packages: management installs only `zdn`;
the optional wallet installs only `ironwood-wallet`. They write those exact names
under `/usr/local/bin`, so installation can replace existing files there. Neither
package contains wallet data, credentials, node inputs or the Linux host helper.
Keep matching sources, source maps and notices in the release profiles separately.

```sh
ZDN_PKG="$STAGE/output/zdn-$RELEASE-macos-arm64.pkg"
WALLET_PKG="$STAGE/output/ironwood-wallet-$RELEASE-macos-arm64.pkg"
pkgbuild --root "$STAGE/zdn" --install-location /usr/local/bin \
  --ownership recommended --identifier io.github.jonwalch.zdn \
  --version "$PACKAGE_VERSION" --sign "$INSTALLER_IDENTITY" --timestamp "$ZDN_PKG"
pkgbuild --root "$STAGE/wallet" --install-location /usr/local/bin \
  --ownership recommended --identifier io.github.jonwalch.ironwood-wallet \
  --version "$PACKAGE_VERSION" --sign "$INSTALLER_IDENTITY" --timestamp "$WALLET_PKG"

for package in "$ZDN_PKG" "$WALLET_PKG"; do
  pkgutil --check-signature "$package"
done
```

Stop and inspect both results. Require the intended Developer ID Installer
authority and team before authorizing submission:

```sh
for package in "$ZDN_PKG" "$WALLET_PKG"; do
  xcrun notarytool submit "$package" --keychain-profile "$NOTARY_PROFILE" \
    --wait --output-format json > "$package.notary.json"
done
```

Submission uploads the packages to Apple; it does **not** publish a GitHub release.
For each JSON response, save its submission `id`, require `status: Accepted`, and
download/review the complete log, including warnings. A timeout or interrupted
wait is an unknown outcome: use `notarytool history`/`info` to identify and inspect
the existing submission before resubmitting. Never treat command exit alone as acceptance.

For **each** accepted package, replace `SUBMISSION_ID` and select its exact path:

```sh
PACKAGE="$ZDN_PKG"
SUBMISSION_ID=REPLACE_WITH_THIS_PACKAGES_ACCEPTED_ID
xcrun notarytool log "$SUBMISSION_ID" --keychain-profile "$NOTARY_PROFILE" \
  "$PACKAGE.notary-log.json"
xcrun stapler staple "$PACKAGE"
xcrun stapler validate "$PACKAGE"
pkgutil --check-signature "$PACKAGE"
spctl --assess --type install --verbose=4 "$PACKAGE"
```

Repeat with `WALLET_PKG` and its own submission ID. Stop on rejection; never
disable assessment or strip quarantine. The final `.pkg` must carry its ticket
and pass installer signature, staple and Gatekeeper checks. Apple cannot staple
to a bare executable or ZIP archive; this is why these downloads use `.pkg`.

## 5. Freeze new identities and qualify before publication

```sh
shasum -a 256 "$ZDN_INPUT" "$WALLET_INPUT" \
  "$STAGE/zdn/zdn" "$STAGE/wallet/ironwood-wallet" "$ZDN_PKG" "$WALLET_PKG"
stat -f '%N %z bytes' "$ZDN_PKG" "$WALLET_PKG"
```

Confirm original input hashes are unchanged. Preserve input/output hashes,
source/lock/toolchain identities, code identifiers, certificate team/fingerprints,
signed-executable hashes, package versions, accepted submission IDs, notary logs
and final stapled-package hashes. Signing changes executable bytes and stapling
changes package bytes: compute distribution checksums **after** those steps.
Do not rebuild, strip or rewrite a signed payload afterward.

Before claiming installation support:

- Inspect package payloads and receipts: exactly the intended executable per
  package, no install scripts, extra files, private keys or owner data. Preserve
  matching sources/licenses/notices; signing does not resolve attribution gaps.
- Arrange an explicitly authorized download/install test using a fresh browser
  profile and a clean test machine/account with OS protections unchanged. Use
  the **exact candidate packages**, not unquarantined build-directory copies.
  Avoid overwriting an existing `/usr/local/bin/zdn` or wallet without consent.
  Verify browser-acquired quarantine, checksums and normal installer assessment.
  Any temporary hosting or candidate publication requires its own authorization.
- After ordinary authorized installation, compare installed executable hashes
  with the signed payloads. Bound actual `zdn --version`, help/reference and wallet
  `capabilities` launches, then repeat the no-cloud consumer checks and ordinary
  native suite with the signed candidates where applicable. Record actual
  launch results; notarization acceptance alone does not prove execution works.
- Keep browser installation qualification separate from AWS/node/payment/recovery
  qualification. Those workloads still require their own exact-scope approval.
- Prepare **new** release profiles/index/checksums and instructions for package
  installation, retaining the separately pinned Linux helper. Publish only after
  explicit approval. Do not replace Preview 2 assets, move its tag or reuse its
  checksum pins. Old Mac onboarding stays blocked until the new path passes.

The preparation commands do not install the packages. No automatic GitHub upload,
workflow dispatch, installation, keychain ACL change or release publication is
configured. Keep failed stages and their receipts; do not blindly restart from
signing or erase the evidence. Preserve the stage until all required receipts and
final artifacts have been safely retained, then remove only that disposable stage.

## Apple references

- [Developer ID certificate creation and required roles](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)
- [Notarization protections and signing requirements](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Custom notarization, credentials, logs and stapling limitations](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
- [Resolving signing and notarization issues](https://developer.apple.com/documentation/security/resolving-common-notarization-issues)
