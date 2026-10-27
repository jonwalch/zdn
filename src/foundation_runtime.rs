//! Explicit delivery selection for fresh native foundation-only hosts.
use crate::{
    aws::TeamDefinition,
    devnet::{self, Artifact},
    foundation::Deployment,
    host::S3Object,
    infra::{FoundationSpec, PulumiProgram},
};
use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::Read,
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};

pub const HELPER: &str = "foundation-runtime/zdn";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FoundationRuntime {
    pub protocol: String,
    pub helper: Artifact,
}

impl FoundationRuntime {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_runtime.stage")
    )]
    pub fn stage(source: &Path, directory: &Path) -> Result<Self> {
        let staging = tempfile::tempdir()?;
        let snapshot = staging.path().join("zdn");
        let helper = devnet::snapshot_file(source, &snapshot, devnet::MAX_HELPER_BYTES)?;
        devnet::validate_helper_file(&snapshot)?;
        crate::foundation::private_directory(&directory.join("foundation-runtime"))?;
        devnet::publish_snapshot(&snapshot, &directory.join(HELPER), &helper)?;
        Ok(Self {
            protocol: crate::foundation_host::PROTOCOL.into(),
            helper,
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol == crate::foundation_host::PROTOCOL,
            "unsupported foundation runtime protocol"
        );
        devnet::validate_hash(&self.helper.sha256)?;
        ensure!(
            self.helper.bytes >= 64 && self.helper.bytes <= devnet::MAX_HELPER_BYTES,
            "invalid foundation runtime size"
        );
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_runtime.verify_local")
    )]
    pub fn verify_local(&self, directory: &Path) -> Result<()> {
        self.validate()?;
        ensure!(
            devnet::hash_file(&directory.join(HELPER), devnet::MAX_HELPER_BYTES)? == self.helper,
            "foundation runtime bytes changed"
        );
        devnet::validate_helper_file(&directory.join(HELPER))
    }

    pub fn object(&self, team: &TeamDefinition, spec: &FoundationSpec) -> Result<S3Object> {
        self.validate()?;
        let object = S3Object {
            bucket: team.backend_bucket()?.into(),
            key: format!(
                "{}{}/foundation-zdn",
                devnet::artifact_prefix(team, spec),
                self.helper.sha256
            ),
            owner_account: team.aws.account_id.clone(),
            region: team.aws.region.clone(),
            bytes: self.helper.bytes,
            sha256: self.helper.sha256.clone(),
        };
        object.validate()?;
        Ok(object)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_runtime.render")
    )]
    pub fn render(&self, base: PulumiProgram, deployment: &Deployment) -> Result<PulumiProgram> {
        let object = self.object(&deployment.team, &deployment.spec)?;
        let prelude = deployment.spec.cloud_init()?;
        let size = match deployment.spec.size {
            crate::config::Size::Small => "small",
            crate::config::Size::Medium => "medium",
            crate::config::Size::Large => "large",
        };
        let script = format!(
            r#"{prelude}
# One deadline includes download, integrity/capability checks and service install.
timeout --signal=TERM --kill-after=5s 180s /bin/bash <<'ZDN_FOUNDATION_RUNTIME'
set -euo pipefail
unset POSIXLY_CORRECT
set +o posix
umask 077
work=$(mktemp -d /opt/zdn/.foundation.XXXXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
trap 'exit 143' TERM HUP
trap 'exit 130' INT
if ! (ulimit -f {blocks} || exit 1; exec aws s3api get-object --bucket '{bucket}' --key '{key}' --expected-bucket-owner '{owner}' --region '{region}' "$work/zdn") >/dev/null 2>&1; then
    echo 'foundation helper download failed' >&2; exit 1
fi
test "$(stat -c '%s' -- "$work/zdn")" = '{bytes}'
printf '%s  %s\n' '{digest}' "$work/zdn" | sha256sum --check --status
chmod 0700 -- "$work/zdn"
"$work/zdn" __runtime-capabilities --require zdn-foundation-health/v1alpha1 >/dev/null 2>&1
mv -T -- "$work/zdn" /opt/zdn/foundation-zdn
cat >/etc/systemd/system/zdn-foundation.service <<'UNIT'
[Unit]
Description=zdn private native foundation readiness fixture
After=network-online.target docker.service amazon-ssm-agent.service zdn-chain.service
Requires=docker.service amazon-ssm-agent.service zdn-chain.service
[Service]
Type=simple
ExecStart=/opt/zdn/foundation-zdn __foundation-serve --protocol zdn-foundation-health/v1alpha1 --network-id {network} --size {size}
Restart=on-failure
RestartSec=5
MemoryMax=268435456
CPUQuota=25%
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/zdn
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
ZDN_FOUNDATION_RUNTIME
systemctl enable --now zdn-chain.service zdn-foundation.service
"#,
            blocks = object.bytes.div_ceil(1024),
            bucket = object.bucket,
            key = object.key,
            owner = object.owner_account,
            region = object.region,
            bytes = object.bytes,
            digest = object.sha256,
            network = deployment.spec.network_id,
        );
        ensure!(
            script.len() <= 16 * 1024,
            "native foundation user data exceeds 16 KiB"
        );
        let mut value = serde_json::to_value(base)?;
        value["resources"]["host"]["properties"]["userData"] = json!(script);
        value["resources"]["hostArtifactsPolicy"] = json!({"name":deployment.spec.resource_name("host-artifacts-policy"),"type":"aws:iam:RolePolicyAttachment","properties":{"role":"${hostRole.name}","policyArn":crate::access::runtime_data_policy_arn(&deployment.team)},"options":{"provider":"${provider}"}});
        value["resources"]["host"]["options"]["dependsOn"]
            .as_array_mut()
            .context("foundation host dependencies missing")?
            .push(json!("${hostArtifactsPolicy}"));
        let program: PulumiProgram = serde_json::from_value(value)?;
        program.validate_references()?;
        Ok(program)
    }
}

/// Read only loopback readiness. Disable proxies/redirects and buffer a complete
/// bounded response before exposing stdout. One budget includes all retries.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_runtime.fetch")
)]
pub fn fetch(endpoint: SocketAddr, budget: Duration) -> Result<String> {
    ensure!(
        endpoint.is_ipv4() && endpoint.ip().is_loopback() && endpoint.port() != 0,
        "foundation health requires IPv4 loopback"
    );
    let deadline = Instant::now() + budget;
    for _ in 0..100 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "foundation health deadline reached");
        let agent = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .redirects(0)
            .timeout(remaining.min(Duration::from_secs(5)))
            .build();
        if let Ok(response) = agent.get(&format!("http://{endpoint}/health")).call() {
            ensure!(
                response.status() == 200,
                "unexpected foundation health status"
            );
            let mut bytes = Vec::new();
            response
                .into_reader()
                .take(16385)
                .read_to_end(&mut bytes)
                .map_err(|_| eyre::eyre!("foundation health response read failed"))?;
            ensure!(
                bytes.len() <= 16384,
                "foundation health response exceeds limit"
            );
            ensure!(
                Instant::now() <= deadline,
                "foundation health deadline reached"
            );
            return String::from_utf8(bytes).context("invalid foundation health UTF-8");
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(remaining.min(Duration::from_secs(5)));
    }
    eyre::bail!("foundation health did not become ready")
}
