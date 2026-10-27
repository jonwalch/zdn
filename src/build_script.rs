//! Native executor recipe and optional, non-authoritative intermediate layer cache.

use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::{ensure, ContextCompat, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{build::BuildContract, build_infra::BuildInfrastructure};

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_script.validate_project_cache")
)]
pub(crate) fn validate_project_cache(project: &Value, infra: &BuildInfrastructure) -> Result<()> {
    let cache = &project["cache"];
    ensure!(
        cache["type"] == "S3"
            && cache["location"] == format!("{}/cache", infra.source_bucket)
            && cache["cacheNamespace"] == infra.project_name
            && cache.get("pathPrefix").is_none_or(|v| v == "")
            && cache
                .get("modes")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "CodeBuild project must use the team-scoped S3 layer cache"
    );
    Ok(())
}

/// JSON is also YAML. Keep all shell interpolation generated from validated
/// contract fields, fixed infrastructure, UUIDs, or single-quoted literals.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_script.buildspec")
)]
pub fn native_buildspec(
    contract: &BuildContract,
    infra: &BuildInfrastructure,
    attempt: Uuid,
    version: &str,
    exporter: &crate::build_job::NativeExporter,
) -> Result<String> {
    exporter.validate()?;
    ensure!(
        exporter.version.is_some(),
        "native exporter object version missing"
    );
    render(contract, infra, attempt, version, exporter)
}

fn render(
    contract: &BuildContract,
    infra: &BuildInfrastructure,
    attempt: Uuid,
    version: &str,
    exporter: &crate::build_job::NativeExporter,
) -> Result<String> {
    contract.validate()?;
    // Infrastructure normally comes from for_team, but its fields are public.
    // Reject metacharacters even for callers constructing their own value.
    for value in [
        &infra.source_bucket,
        &infra.project_name,
        &infra.account_id,
        &infra.region,
        &infra.repository,
        &infra.repository_uri,
    ] {
        ensure!(
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._/-:".contains(&b)),
            "unsafe build infrastructure identifier"
        );
    }
    ensure!(
        infra
            .project_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "unsafe layer cache namespace"
    );
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let contract_b64 = STANDARD.encode(serde_json::to_vec(contract)?);
    let runtime_prepare = format!(
        r#"umask 077
aws s3api get-object --bucket {bucket} --key {key} --version-id {version} --expected-bucket-owner {account} zdn-runtime >/dev/null
test "$(wc -c < zdn-runtime)" -eq {bytes}
echo '{sha256}  zdn-runtime' | sha256sum -c -
chmod 700 zdn-runtime
./zdn-runtime __runtime-capabilities --require {protocol} >/dev/null
printf '%s' '{contract_b64}' | base64 --decode > contract.json
"#,
        bucket = infra.source_bucket,
        key = exporter.key(attempt),
        version = quote(exporter.version.as_deref().unwrap()),
        account = infra.account_id,
        bytes = exporter.helper.bytes,
        sha256 = exporter.helper.sha256,
        protocol = exporter.protocol,
    );
    // No source fingerprint: source changes should reuse intermediate layers.
    // The repository Dockerfile defines the toolchain; BuildKit's content keys
    // invalidate changed recipe/toolchain steps, not a guessed compiler version.
    let recipe = hex::encode(Sha256::digest(serde_json::to_vec(&contract.recipe)?));
    let namespace = format!(
        "{}-linux-amd64-standard7-buildx-local-v1-{recipe}",
        infra.project_name
    );
    let cache_dir = format!("/tmp/zdn-layer-cache/{namespace}");
    let script = format!(
        r#"set -euo pipefail
test "$(uname -m)" = x86_64
mkdir -p /tmp/zdn-build/source
cd /tmp/zdn-build
{runtime_prepare}aws s3api get-object --bucket {bucket} --key sources/{source}.tar --version-id {version} --expected-bucket-owner {account} source.tar >/dev/null
echo '{source}  source.tar' | sha256sum -c -
# Git source is public build context: retain its readable/executable modes for
# non-root Dockerfile users without relaxing private runtime/contract writes.
(umask 022; tar --extract --file source.tar --directory source --no-same-owner --no-same-permissions)
aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin {registry}
# External local caches require a docker-container builder (not the default driver).
docker buildx create --name zdn-native --driver docker-container --use
docker buildx inspect --bootstrap
cache_dir={cache_dir}
cache_next="$cache_dir.next"
mkdir -p "$(dirname "$cache_dir")"
rm -rf "$cache_next"
cache_args=()
if test -f "$cache_dir/index.json"; then
  cache_args=(--cache-from "type=local,src=$cache_dir")
fi
# mode=max exports intermediate dependency/compiler layers, NOT arbitrary
# RUN --mount=type=cache contents. The source Dockerfile remains the contract.
docker buildx build --push --provenance=false --sbom=false --platform linux/amd64 --target runtime "${{cache_args[@]}}" --cache-to "type=local,dest=$cache_next,mode=max,ignore-error=true" -f source/{dockerfile} -t {uri}:{attempt} source/{context}
aws ecr batch-get-image --registry-id {account} --repository-name {repo} --image-ids imageTag={attempt} --accepted-media-types application/vnd.docker.distribution.manifest.v2+json application/vnd.oci.image.manifest.v1+json > registry.json
config_digest=$(jq -er '.images[0].imageManifest | fromjson | .config.digest | select(test("^sha256:[0-9a-f]{{64}}$"))' registry.json)
aws ecr get-download-url-for-layer --registry-id {account} --repository-name {repo} --layer-digest "$config_digest" > config-download.json
./zdn-runtime __build-export --protocol {protocol} --contract contract.json --repository {uri} --registry registry.json --config-download config-download.json --output output
for name in result.json image-manifest.json image-config.json; do
  aws s3api put-object --bucket {bucket} --key results/{attempt}/"$name" --expected-bucket-owner {account} --server-side-encryption AES256 --body output/"$name" >/dev/null
done
# Publish only a completed export, after the image/result checks and uploads.
if test -f "$cache_next/index.json"; then
  rm -rf "$cache_dir.old"
  if test -e "$cache_dir"; then mv "$cache_dir" "$cache_dir.old"; fi
  mv "$cache_next" "$cache_dir"
  rm -rf "$cache_dir.old"
fi
"#,
        bucket = infra.source_bucket,
        source = contract.source_sha256,
        version = quote(version),
        account = infra.account_id,
        region = infra.region,
        registry = infra
            .repository_uri
            .split('/')
            .next()
            .context("registry missing")?,
        repo = infra.repository,
        uri = infra.repository_uri,
        dockerfile = contract.recipe.dockerfile,
        context = contract.recipe.context,
        protocol = exporter.protocol,
        cache_dir = quote(&cache_dir),
    );
    // S3 keyed caches are immutable. A unique key per attempt plus prefix
    // fallback restores a compatible cache and allows subsequent growth.
    Ok(serde_json::to_string(&json!({
        "version":0.2,"env":{"shell":"bash"},
        "phases":{"build":{"commands":[script]}},
        "cache":{"key":format!("{namespace}-{attempt}"),"fallback-keys":[format!("{namespace}-")],"paths":[format!("{cache_dir}/**/*")]}
    }))?)
}
