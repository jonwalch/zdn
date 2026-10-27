//! One refreshable AWS identity for CLI requests and every Pulumi AWS client.
//! Only non-secret instructions are saved. STS credentials travel over stdout
//! to the requesting SDK and are never written to disk by zdn.

use crate::{
    access,
    aws::{self, AwsApi, AwsCli, AwsSelection, TeamDefinition},
    foundation,
};
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialFiles {
    pub config: PathBuf,
    pub empty_credentials: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequest {
    pub version: u32,
    pub source: AwsSelection,
    pub role_arn: String,
    pub source_config: PathBuf,
    pub source_credentials: PathBuf,
}

impl CredentialRequest {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "credentials.credential_request.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported credential request version");
        self.source.validate()?;
        access::iam_resource(&self.role_arn, &self.source.account_id, "role")?;
        for path in [&self.source_config, &self.source_credentials] {
            ensure!(
                path.is_absolute(),
                "credential source paths must be absolute"
            );
            ensure!(
                !path
                    .components()
                    .any(|p| p == std::path::Component::ParentDir),
                "credential source path contains parent traversal"
            );
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "credentials.credential_request.source_environment")
    )]
    pub fn source_environment(
        &self,
        mut environment: BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>> {
        self.validate()?;
        // The outer SDK selects our private config. Restore only the explicitly
        // recorded original sources; never consult that private config again.
        for (key, path) in [
            ("AWS_CONFIG_FILE", &self.source_config),
            ("AWS_SHARED_CREDENTIALS_FILE", &self.source_credentials),
        ] {
            environment.insert(
                key.into(),
                path.to_str()
                    .context("non-UTF-8 credential source path")?
                    .into(),
            );
        }
        self.source.validate_environment(&environment)?;
        Ok(environment)
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "credentials.environment")
)]
pub fn environment() -> Result<BTreeMap<String, String>> {
    std::env::vars_os()
        .map(|(k, v)| {
            Ok((
                k.into_string()
                    .map_err(|_| eyre::eyre!("non-UTF-8 environment name"))?,
                v.into_string()
                    .map_err(|_| eyre::eyre!("non-UTF-8 environment value"))?,
            ))
        })
        .collect()
}

/// A single-profile config plus an empty credentials file prevents an existing
/// static credential with the same profile name from bypassing the role bridge.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "credentials.prepare")
)]
pub fn prepare(
    team: &TeamDefinition,
    selection: &AwsSelection,
    directory: &Path,
    executable: &Path,
    environment: &BTreeMap<String, String>,
) -> Result<Option<CredentialFiles>> {
    team.validate()?;
    selection.validate_environment(environment)?;
    ensure!(
        selection.account_id == team.aws.account_id && selection.region == team.aws.region,
        "credential selection differs from team"
    );
    let Some(access) = &team.deployment else {
        return Ok(None);
    };
    let home = environment
        .get("HOME")
        .map(PathBuf::from)
        .context("HOME is required to resolve source AWS profiles")?;
    let request = CredentialRequest {
        version: 1,
        source: selection.clone(),
        role_arn: access.role_arn.clone(),
        source_config: environment
            .get("AWS_CONFIG_FILE")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".aws/config")),
        source_credentials: environment
            .get("AWS_SHARED_CREDENTIALS_FILE")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".aws/credentials")),
    };
    request.validate()?;
    let identity = hex::encode(Sha256::digest(serde_json::to_vec(&(&request, executable))?));
    let root = directory.join(identity);
    ensure!(
        root.is_absolute() && executable.is_absolute(),
        "credential bridge requires absolute paths"
    );
    foundation::private_directory(directory)?;
    foundation::private_directory(&root)?;
    let request_path = root.join("request.json");
    let files = CredentialFiles {
        config: root.join("config"),
        empty_credentials: root.join("credentials"),
    };
    ensure!(
        request.source_config != files.config
            && request.source_credentials != files.empty_credentials,
        "recursive credential bridge"
    );
    let command = format!(
        "{} __credentials --request {}",
        escape_argument(executable)?,
        escape_argument(&request_path)?
    );
    let section = if selection.profile == "default" {
        "default".into()
    } else {
        format!("profile {}", selection.profile)
    };
    foundation::write_json(&request_path, &request)?;
    foundation::write_private(&files.empty_credentials, b"")?;
    foundation::write_private(
        &files.config,
        format!(
            "[{section}]\nregion = {}\ncredential_process = {command}\n",
            selection.region
        )
        .as_bytes(),
    )?;
    Ok(Some(files))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "credentials.escape_argument")
)]
fn escape_argument(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .context("credential bridge path must be UTF-8")?;
    // The Go SDK's INI parser removes matching quotes around the entire value,
    // even when they belong to separate arguments. Keep the restricted path
    // alphabet and escape spaces without outer quotes: both its POSIX shell and
    // the AWS CLI's shlex parser preserve these argument boundaries.
    ensure!(
        !value.is_empty()
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_. /".contains(&c)),
        "credential bridge path contains unsupported characters"
    );
    Ok(value.replace(' ', "\\ "))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "credentials.apply_files")
)]
pub fn apply_files(
    environment: &mut BTreeMap<String, String>,
    files: &CredentialFiles,
) -> Result<()> {
    for (key, path) in [
        ("AWS_CONFIG_FILE", &files.config),
        ("AWS_SHARED_CREDENTIALS_FILE", &files.empty_credentials),
    ] {
        ensure!(path.is_absolute(), "credential file path must be absolute");
        environment.insert(
            key.into(),
            path.to_str()
                .context("non-UTF-8 credential file path")?
                .into(),
        );
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "credentials.client")
)]
pub fn client(
    team: &TeamDefinition,
    selection: AwsSelection,
    directory: &Path,
) -> Result<(AwsCli, Option<CredentialFiles>)> {
    let mut environment = environment()?;
    let files = prepare(
        team,
        &selection,
        directory,
        &std::env::current_exe()?,
        &environment,
    )?;
    if let Some(files) = &files {
        apply_files(&mut environment, files)?;
    }
    let api = AwsCli::with_environment(selection, "aws", environment)?
        .expect_role(team.deployment.as_ref().map(|a| a.role_arn.clone()))?;
    api.verify_cli_version()?;
    Ok((api, files))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "credentials.verify_role")
)]
pub fn verify_role(identity: &aws::CallerIdentity, role_arn: &str, account: &str) -> Result<()> {
    let name = access::iam_resource(role_arn, account, "role")?
        .rsplit('/')
        .next()
        .unwrap();
    let prefix = format!("arn:aws:sts::{account}:assumed-role/{name}/");
    ensure!(
        identity.account == account
            && identity
                .arn
                .strip_prefix(&prefix)
                .is_some_and(|s| !s.is_empty() && !s.contains('/')),
        "AWS credentials do not match the selected deployment role"
    );
    Ok(())
}

/// Called by AWS SDKs as credential_process. Each call requests a fresh bounded
/// session; Expiration makes the SDK call again before expiry during long runs.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "credentials.issue")
)]
pub fn issue(api: &dyn AwsApi, request: &CredentialRequest) -> Result<Value> {
    request.validate()?;
    aws::verify_identity(api, &request.source)?;
    let result = api.call("sts","assume-role",json!({"RoleArn":request.role_arn,"RoleSessionName":"zdn-deployment","DurationSeconds":3600}),&[])?;
    let identity = aws::CallerIdentity {
        account: request.source.account_id.clone(),
        arn: result
            .pointer("/AssumedRoleUser/Arn")
            .and_then(Value::as_str)
            .context("STS omitted assumed role identity")?
            .into(),
        user_id: result
            .pointer("/AssumedRoleUser/AssumedRoleId")
            .and_then(Value::as_str)
            .context("STS omitted assumed role ID")?
            .into(),
    };
    verify_role(&identity, &request.role_arn, &request.source.account_id)?;
    let credentials = result
        .get("Credentials")
        .context("STS omitted temporary credentials")?;
    let mut output = json!({"Version":1,"AccountId":request.source.account_id});
    for key in [
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "Expiration",
    ] {
        let value = credentials
            .get(key)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && v.len() <= 16384 && !v.chars().any(char::is_control))
            .context("STS returned incomplete temporary credentials")?;
        output[key] = json!(value);
    }
    // AWS may return an offset instead of Z. The SDK parses the exact timestamp;
    // do not omit it or silently turn a session into non-expiring credentials.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    validate_expiration(output["Expiration"].as_str().unwrap(), now)?;
    Ok(output)
}

/// STS returns UTC RFC3339. Reject expired/incomplete sessions before the SDK
/// sees them. Support both AWS UTC spellings and optional fractional seconds.
pub fn validate_expiration(value: &str, now: u64) -> Result<()> {
    let expiry = utc_timestamp(value)?;
    ensure!(
        expiry.saturating_sub(now) > 60,
        "STS credentials are expired or too near expiry"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "credentials.utc_timestamp")
)]
pub(crate) fn utc_timestamp(value: &str) -> Result<u64> {
    let utc = value
        .strip_suffix('Z')
        .or_else(|| value.strip_suffix("+00:00"))
        .context("STS expiration must be UTC")?;
    let (date, fraction) = utc
        .split_once('.')
        .map_or((utc, None), |(a, b)| (a, Some(b)));
    ensure!(
        date.len() == 19
            && date.is_ascii()
            && date.as_bytes()[4] == b'-'
            && date.as_bytes()[7] == b'-'
            && date.as_bytes()[10] == b'T'
            && date.as_bytes()[13] == b':'
            && date.as_bytes()[16] == b':',
        "invalid STS expiration"
    );
    ensure!(
        fraction
            .is_none_or(|s| !s.is_empty() && s.len() <= 9 && s.bytes().all(|b| b.is_ascii_digit())),
        "invalid STS expiration fraction"
    );
    let number = |range: std::ops::Range<usize>| -> Result<u64> {
        ensure!(
            date[range.clone()].bytes().all(|b| b.is_ascii_digit()),
            "invalid STS expiration component"
        );
        Ok(date[range].parse()?)
    };
    let (year, month, day, hour, minute, second) = (
        number(0..4)?,
        number(5..7)?,
        number(8..10)?,
        number(11..13)?,
        number(14..16)?,
        number(17..19)?,
    );
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(
        (1970..=9999).contains(&year)
            && (1..=12).contains(&month)
            && day > 0
            && day <= months[(month - 1) as usize]
            && hour < 24
            && minute < 60
            && second < 60,
        "invalid STS expiration date"
    );
    let days: u64 = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + months[..(month - 1) as usize].iter().sum::<u64>()
        + day
        - 1;
    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "credentials.run_process")
)]
pub fn run_process(path: &Path) -> Result<Value> {
    let request: CredentialRequest = foundation::read_json(path)?;
    let api = AwsCli::with_environment(
        request.source.clone(),
        "aws",
        request.source_environment(environment()?)?,
    )?
    .within_credential_process();
    issue(&api, &request)
}
