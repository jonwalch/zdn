//! Bounded shell transport for a hash-bound native installer.
//! Adapted from `capacity_bootstrap`; published transports are
//! unchanged. Marker checks are lstat-then-no-follow-open, not descriptor binding
//! or protection against hostile root filesystem races.

use eyre::{ensure, Result};

pub const PROTOCOL: &str = "zdn-installer-fetch/v1alpha2";
pub const LEGACY_PROTOCOL: &str = "zdn-installer-fetch/v1alpha1";

pub fn supports(protocol: &str) -> bool {
    matches!(protocol, PROTOCOL | LEGACY_PROTOCOL)
}

pub fn render(object: &crate::host::S3Object, ssm_timeout: u32) -> Result<String> {
    render_selected(PROTOCOL, object, ssm_timeout)
}

/// Saved selections must retain their complete historical SSM command bytes.
pub fn render_selected(
    protocol: &str,
    object: &crate::host::S3Object,
    ssm_timeout: u32,
) -> Result<String> {
    ensure!(supports(protocol), "unsupported installer-fetch protocol");
    object.validate()?;
    ensure!(
        (30..=7200).contains(&ssm_timeout),
        "invalid installer SSM timeout"
    );
    // Leave room for the outer ten-second kill grace and cleanup before SSM
    // stops the command. Gateway installs have only 600s, nodes/updates 7200s.
    let deadline = (ssm_timeout - 20).min(6500);
    // GNU timeout can deliver TERM both directly and to the process group.
    // Disable repeats before entering EXIT cleanup, not just inside cleanup.
    // The empty legacy expansion preserves already-journaled v1alpha1 bytes.
    let ignore_signals = if protocol == LEGACY_PROTOCOL {
        ""
    } else {
        "trap \"\" INT TERM HUP; "
    };
    Ok(format!(
        r#"#!/bin/bash
# GNU timeout owns the outer group. Never use --foreground.
exec timeout --signal=TERM --kill-after=10s {deadline}s /bin/bash <<'ZDN_INSTALLER_BOOTSTRAP'
set -euo pipefail
export LC_ALL=C
unset POSIXLY_CORRECT
set +o posix
umask 077
work=''
child=''
# Each phase has its own timeout group. Forward cancellation explicitly, also
# removing descendants left behind by a successfully exiting phase leader.
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
cleanup() {{ {ignore_signals}stop_group; if [[ -n "$work" ]]; then rm -rf -- "$work"; fi; }}
trap cleanup EXIT
trap '{ignore_signals}exit 130' INT
trap '{ignore_signals}exit 143' TERM HUP
fail() {{ printf '%s\n' "$1" >&2; exit 1; }}
work=$(mktemp -d /tmp/zdn-installer.XXXXXXXXXX) || fail 'installer temporary directory failed'
printf 'zdn-host-prerequisites/v1alpha1\n' > "$work/expected"
marker=/etc/zdn-prerequisites-ready
# Monotonic rounding plus one reserved second bounds polling below 600s.
read -r uptime _ < /proc/uptime
deadline=$(( ${{uptime%%.*}} + 599 ))
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
# Explicitly non-POSIX Bash ulimit -f units are 1024 bytes. The limit
# applies only to AWS, not the verified installer or its runtime outputs.
timeout --signal=TERM --kill-after=5s 115s /bin/bash -c 'ulimit -f {blocks} || exit 1; exec aws s3api get-object --bucket "{bucket}" --key "{key}" --expected-bucket-owner "{owner}" --region "{region}" "$1"' bash "$work/installer" >/dev/null 2>&1 &
child=$!
status=0
wait "$child" || status=$?
stop_group
(( status == 0 )) || fail 'installer download failed'
[[ $(stat -c '%s' -- "$work/installer" 2>/dev/null) == '{bytes}' ]] || fail 'installer size mismatch'
printf '%s  %s\n' '{digest}' "$work/installer" | sha256sum --check --status 2>/dev/null || fail 'installer digest mismatch'
chmod 0600 -- "$work/installer" || fail 'installer permissions failed'
# Preserve installer stdout, but not provider/runtime diagnostics or error text.
timeout --signal=TERM --kill-after=5s 5295s /bin/bash "$work/installer" 2>/dev/null &
child=$!
status=0
wait "$child" || status=$?
stop_group
exit "$status"
ZDN_INSTALLER_BOOTSTRAP
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
