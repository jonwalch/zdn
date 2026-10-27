//! Additive hash-bound installer payload. The existing installer-fetch
//! transport supplies prerequisite waiting and authenticates these exact bytes.
//! No legacy script or saved SSM selection is changed by this renderer.

use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::Result;

use super::{Manifest, INSTALL_PROTOCOL};

pub fn render(manifest: &Manifest) -> Result<String> {
    let bytes = manifest.bytes()?;
    let helper = &manifest.runtime.helper;
    // All interpolated provider fields are validated by Manifest; the manifest
    // itself is base64 data, never shell syntax. This fits the existing node
    // installer's 5295s phase and 7200s SSM envelope, not the gateway envelope.
    Ok(format!(
        r#"#!/bin/bash
exec timeout --signal=TERM --kill-after=10s 5000s /bin/bash <<'ZDN_NATIVE_HOST_INSTALL'
set -euo pipefail
export LC_ALL=C
unset POSIXLY_CORRECT
set +o posix
umask 077
work=''
child=''
stop_group() {{
    if [[ -n "$child" ]]; then
        if kill -TERM -- "-$child" 2>/dev/null; then
            sleep 1
            kill -KILL -- "-$child" 2>/dev/null || :
        fi
        wait "$child" 2>/dev/null || :
        child=''
    fi
}}
cleanup() {{ trap "" INT TERM HUP; stop_group; if [[ -n "$work" ]]; then rm -rf -- "$work"; fi; }}
trap cleanup EXIT
trap 'trap "" INT TERM HUP; exit 130' INT
trap 'trap "" INT TERM HUP; exit 143' TERM HUP
fail() {{ printf '%s\n' "$1" >&2; exit 1; }}
work=$(mktemp -d /tmp/zdn-native-install.XXXXXXXXXX) || fail 'native install staging failed'
printf '%s' '{manifest}' | base64 --decode > "$work/manifest" || fail 'native manifest decode failed'
timeout --signal=TERM --kill-after=5s 115s /bin/bash -c 'ulimit -f {blocks} || exit 1; exec aws s3api get-object --bucket "{bucket}" --key "{key}" --expected-bucket-owner "{owner}" --region "{region}" "$1"' bash "$work/zdn" >/dev/null 2>&1 &
child=$!
status=0
wait "$child" || status=$?
stop_group
(( status == 0 )) || fail 'native runtime download failed'
[[ $(stat -c '%s' -- "$work/zdn" 2>/dev/null) == '{bytes}' ]] || fail 'native runtime size mismatch'
printf '%s  %s\n' '{digest}' "$work/zdn" | sha256sum --check --status 2>/dev/null || fail 'native runtime digest mismatch'
chmod 0700 -- "$work/zdn" || fail 'native runtime permissions failed'
timeout --signal=TERM --kill-after=5s 10s "$work/zdn" __runtime-capabilities --require {protocol} >/dev/null 2>&1 &
child=$!
status=0
wait "$child" || status=$?
stop_group
(( status == 0 )) || fail 'native installer capability unavailable'
timeout --signal=TERM --kill-after=10s 4805s "$work/zdn" __host-install --protocol {protocol} < "$work/manifest" 2>/dev/null &
child=$!
status=0
wait "$child" || status=$?
stop_group
exit "$status"
ZDN_NATIVE_HOST_INSTALL
"#,
        manifest = STANDARD.encode(bytes),
        blocks = helper.bytes.div_ceil(1024),
        bucket = helper.bucket,
        key = helper.key,
        owner = helper.owner_account,
        region = helper.region,
        bytes = helper.bytes,
        digest = helper.sha256,
        protocol = INSTALL_PROTOCOL,
    ))
}
