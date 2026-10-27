//! Bounded transport for the content-pinned native capacity observer.
//!
//! Marker inspection deliberately retains lstat-then-no-follow-open semantics,
//! not descriptor metadata binding or protection against a hostile root.

use eyre::Result;

pub fn render(object: &crate::host::S3Object) -> Result<String> {
    object.validate()?;
    // Validation excludes shell metacharacters in every interpolated field.
    Ok(format!(
        r#"#!/bin/bash
# GNU timeout owns the process group, including AWS and helper descendants.
# Do not use --foreground: cancellation must reach the entire group.
exec timeout --signal=TERM --kill-after=5s 1100s /bin/bash <<'ZDN_CAPACITY_BOOTSTRAP'
set -euo pipefail
export LC_ALL=C
unset POSIXLY_CORRECT
set +o posix
umask 077
work=''
cleanup() {{ if [[ -n "$work" ]]; then rm -rf -- "$work"; fi; }}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
fail() {{ printf '%s\n' "$1" >&2; exit 1; }}
work=$(mktemp -d /tmp/zdn-capacity.XXXXXXXXXX) || fail 'capacity temporary directory failed'
printf 'zdn-host-prerequisites/v1alpha1\n' > "$work/expected"
marker=/etc/zdn-prerequisites-ready
# /proc/uptime is monotonic. Rounding down and reserving a second keeps
# the polling budget below 900 seconds, including the final sleep.
read -r uptime _ < /proc/uptime
deadline=$(( ${{uptime%%.*}} + 899 ))
while true; do
    if metadata=$(stat -c '%u:%a:%f' -- "$marker" 2>/dev/null); then
        [[ "$metadata" =~ ^0:600:([0-9a-f]+)$ ]] || fail 'invalid host prerequisite marker'
        (( (16#${{BASH_REMATCH[1]}} & 0170000) == 0100000 )) || fail 'invalid host prerequisite marker'
        dd if="$marker" of="$work/actual" bs=1 count=33 iflag=nofollow,nonblock status=none 2>/dev/null || fail 'invalid host prerequisite marker'
        cmp -s -- "$work/expected" "$work/actual" || fail 'unexpected host prerequisite marker'
        break
    fi
    [[ ! -e "$marker" && ! -L "$marker" ]] || fail 'invalid host prerequisite marker'
    read -r uptime _ < /proc/uptime
    (( ${{uptime%%.*}} < deadline )) || fail 'host prerequisites did not finish'
    sleep 1
done
# Bash's non-POSIX ulimit -f unit is explicitly 1024 bytes. Apply only
# to the downloader; the pinned executable's exact byte count is checked next.
if ! (ulimit -f {blocks} || exit 1; exec aws s3api get-object --bucket '{bucket}' --key '{key}' --expected-bucket-owner '{owner}' --region '{region}' "$work/helper") >/dev/null 2>&1; then
    fail 'capacity helper download failed'
fi
[[ $(stat -c '%s' -- "$work/helper" 2>/dev/null) == '{bytes}' ]] || fail 'capacity helper size mismatch'
printf '%s  %s\n' '{digest}' "$work/helper" | sha256sum --check --status 2>/dev/null || fail 'capacity helper digest mismatch'
chmod 0700 -- "$work/helper" || fail 'capacity helper permissions failed'
"$work/helper" __runtime-capabilities --require zdn-host-capacity/v1alpha1 >/dev/null 2>&1 || fail 'capacity helper capability check failed'
"$work/helper" __host-capacity --protocol zdn-host-capacity/v1alpha1 >"$work/observation" 2>/dev/null || fail 'capacity observation failed'
cat -- "$work/observation"
ZDN_CAPACITY_BOOTSTRAP
"#,
        blocks = object.bytes.div_ceil(1024),
        bucket = object.bucket,
        key = object.key,
        owner = object.owner_account,
        region = object.region,
        bytes = object.bytes,
        digest = object.sha256,
    ))
}
