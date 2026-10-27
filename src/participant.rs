//! Administrator-owned private-client grants, independent of deployment state
//! access. A participant receives only the endpoint file and their own identity.

use crate::{
    access,
    aws::{self, AwsApi, AwsApiError, AwsSelection, TeamDefinition},
    endpoints::{ownership_tags, EndpointFile},
    foundation,
    pulumi::{
        AwsContext, ManagedTools, PulumiClient, PulumiRunner, PulumiWorkspace, RunControl,
        SystemPulumiRunner,
    },
    state::StateStore,
};
use eyre::{ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub const POLICY_NAME: &str = "zdn-private-services";
pub const PROJECT_DIRECTORY: &str = "project-v2";
const MAX_LOCAL_BYTES: usize = 128 * 1024;

// Only recognized as an upgrade input. Rendering and final IAM verification
// always require the current principal-bound session names.
fn legacy_trust(request: &ParticipantRequest) -> Value {
    let principals: BTreeSet<_> = request.trusted_principals.iter().collect();
    json!({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":principals}
    }]})
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParticipantRequest {
    pub team: TeamDefinition,
    pub endpoints: EndpointFile,
    pub administrator: AwsSelection,
    pub trusted_principals: Vec<String>,
}

impl ParticipantRequest {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "participant.participant_request.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        self.team.validate()?;
        self.endpoints.validate()?;
        self.administrator.validate()?;
        ensure!(
            self.team.scope() == self.endpoints.scope
                && self.team.bootstrap_id == self.endpoints.bootstrap_id,
            "participant endpoint file belongs to a different team, account, region, or bootstrap"
        );
        ensure!(
            self.administrator.account_id == self.team.aws.account_id
                && self.administrator.region == self.team.aws.region,
            "participant administrator selection differs from team"
        );
        self.endpoints
            .participant_trust_policy(&self.trusted_principals)?;
        Ok(())
    }

    pub fn normalized(&self) -> Result<Self> {
        self.validate()?;
        let mut normalized = self.clone();
        normalized.trusted_principals.sort();
        Ok(normalized)
    }

    pub fn stack_name(&self) -> String {
        format!("zdn-participant-{}", self.endpoints.network_id.simple())
    }

    pub fn render(&self) -> Result<Value> {
        self.validate()?;
        self.endpoints
            .render_participant(&self.administrator, &self.trusted_principals)
    }
}

/// Create the receipt hierarchy inside the already validated local state root.
/// Each new component is private. Existing components must be real directories;
/// UUID-derived names cannot escape this namespace. Unix uses directory-relative
/// operations so a component replaced by a symlink cannot redirect creation.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "participant.receipt_directory")
)]
pub fn receipt_directory(store: &StateStore, request: &ParticipantRequest) -> Result<PathBuf> {
    request.validate()?;
    let components = [
        "participants".to_owned(),
        request.team.bootstrap_id.to_string(),
        request.endpoints.network_id.to_string(),
    ];
    let mut directory = store.root().to_path_buf();
    #[cfg(unix)]
    {
        use nix::{
            errno::Errno,
            fcntl::{open, openat, OFlag},
            sys::stat::{mkdirat, Mode},
        };
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let mut parent =
            open(store.root(), flags, Mode::empty()).context("open participant state root")?;
        for component in components {
            match mkdirat(&parent, component.as_str(), Mode::S_IRWXU) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(error) => return Err(error).context("create participant receipt directory"),
            }
            parent = openat(&parent, component.as_str(), flags, Mode::empty())
                .context("participant path component must be a real directory, not a symlink")?;
            directory.push(component);
        }
    }
    #[cfg(not(unix))]
    {
        ensure!(
            fs::symlink_metadata(store.root())?.is_dir(),
            "participant state root must be a real directory"
        );
        for component in components {
            directory.push(component);
            foundation::private_directory(&directory)?;
        }
    }
    Ok(directory)
}

/// Fakeable stack boundary. configure verifies checkpoint ownership before any
/// apply, including an explicit recovery after a partial previous apply.
pub trait ParticipantStack {
    fn exists(&mut self) -> Result<bool>;
    fn prepare(&mut self, create: bool) -> Result<()>;
    fn refresh(&mut self) -> Result<()>;
    fn configure(&mut self, request: &ParticipantRequest) -> Result<()>;
    fn apply(&mut self) -> Result<()>;
    fn outputs(&mut self) -> Result<Value>;
}

pub struct ParticipantClient<R> {
    pub client: PulumiClient<R>,
    pub cancel: Arc<AtomicBool>,
}

fn control(cancel: &AtomicBool) -> Result<RunControl> {
    Ok(if cancel.load(Ordering::SeqCst) {
        RunControl::Cancel
    } else {
        RunControl::Continue
    })
}

impl<R: PulumiRunner> ParticipantStack for ParticipantClient<R> {
    fn exists(&mut self) -> Result<bool> {
        self.client.stack_exists(&mut || control(&self.cancel))
    }
    fn prepare(&mut self, create: bool) -> Result<()> {
        self.client
            .prepare_stack(create, &mut || control(&self.cancel))
    }
    fn refresh(&mut self) -> Result<()> {
        self.client.refresh(&mut || control(&self.cancel))
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "participant.participant_client.configure")
    )]
    fn configure(&mut self, request: &ParticipantRequest) -> Result<()> {
        request.validate()?;
        let workspace = &self.client.workspace;
        ensure!(
            workspace.project == "zdn-participant"
                && workspace.stack == request.stack_name()
                && workspace.backend_url == access::admin_backend(&request.team)?
                && workspace.secrets_provider == request.team.secrets_provider()
                && workspace.aws.profile == request.administrator.profile
                && workspace.aws.account_id == request.administrator.account_id
                && workspace.aws.region == request.administrator.region,
            "participant request differs from the selected stack"
        );
        let export = self
            .client
            .participant_export(&mut || control(&self.cancel))?;
        validate_checkpoint(request, &export)?;
        let prepared: Value = serde_yaml::from_slice(
            &read_regular(&workspace.work_dir.join("Pulumi.yaml"))?
                .context("prepared participant project is missing")?,
        )
        .context("invalid prepared participant project")?;
        ensure!(
            prepared == request.render()?,
            "prepared participant program differs from immutable request"
        );
        Ok(())
    }
    fn apply(&mut self) -> Result<()> {
        self.client.preview(&mut || control(&self.cancel))?;
        self.client.up(&mut || control(&self.cancel))
    }
    fn outputs(&mut self) -> Result<Value> {
        self.client
            .participant_outputs(&mut || control(&self.cancel))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParticipantReceipt {
    pub version: u32,
    pub request: ParticipantRequest,
    pub stack_started: bool,
    pub uncertain: bool,
    pub complete: bool,
}

struct ParticipantLock(fs::File);
impl Drop for ParticipantLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

/// Save intent before effects. Unknown existing stacks/roles are never adopted.
/// This creates or repeats the same grant; changing participants or instances is
/// a separate administrator operation and cannot be smuggled into recovery.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "participant.provision")
)]
pub fn provision(
    api: &dyn AwsApi,
    request: &ParticipantRequest,
    directory: &Path,
    stack: &mut dyn ParticipantStack,
    reconcile: bool,
) -> Result<String> {
    let request = request.normalized()?;
    foundation::private_directory(directory)?;
    let lock_path = directory.join("participant.lock");
    if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
        ensure!(
            metadata.is_file(),
            "participant lock must be a regular file"
        );
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path)?;
    lock.try_lock_exclusive()
        .context("another participant setup holds the local lock")?;
    let _lock = ParticipantLock(lock);
    ensure!(
        !directory.join("removal.json").try_exists()?,
        "participant removal has begun; this grant cannot be reprovisioned"
    );
    let path = directory.join("participant.json");
    let saved = read_receipt(&path, &request)?;
    ensure!(
        !saved.as_ref().is_some_and(|r| r.uncertain) || reconcile,
        "participant apply has an uncertain outcome; inspect the stack and retry with --reconcile"
    );
    // Administrator-owned state is checked before any stack mutation. Callers
    // who only connect never execute these backend or IAM reads.
    aws::verify_backend(api, &request.administrator, &request.team)?;
    request.endpoints.validate_live_documents(api)?;
    // A failed read-only preflight must not create a grant receipt that later
    // requires deletion ownership. Preserve existing recovery receipts verbatim.
    let mut receipt = if let Some(saved) = saved {
        saved
    } else {
        let receipt = ParticipantReceipt {
            version: 1,
            request: request.clone(),
            stack_started: false,
            uncertain: false,
            complete: false,
        };
        foundation::write_json(&path, &receipt)?;
        receipt
    };
    let exists = stack.exists()?;
    ensure!(
        !exists || receipt.stack_started,
        "participant stack exists without a local ownership receipt; recover its original receipt"
    );
    ensure!(
        exists || !receipt.complete,
        "completed participant stack is missing; investigate instead of recreating IAM resources"
    );
    if !exists {
        let role = api.call(
            "iam",
            "get-role",
            json!({"RoleName":request.endpoints.participant_role_name()}),
            &[],
        );
        match role {
            Err(error)
                if error.downcast_ref::<AwsApiError>().is_some_and(|e| {
                    matches!(e.code.as_str(), "NoSuchEntity" | "NoSuchEntityException")
                }) => {}
            Err(error) => return Err(error),
            Ok(_) => eyre::bail!(
                "participant role exists without an owned stack; recover its original checkpoint"
            ),
        }
    }
    receipt.stack_started = true;
    receipt.uncertain = true;
    foundation::write_json(&path, &receipt)?;
    stack.prepare(!exists)?;
    if reconcile && exists {
        stack.refresh()?;
    }
    stack.configure(&request)?;
    stack.apply()?;
    ensure!(
        stack.outputs()? == json!({"roleArn":request.endpoints.participant_role_arn()}),
        "participant outputs differ from the requested role"
    );
    verify_role(api, &request)?;
    receipt.complete = true;
    receipt.uncertain = false;
    foundation::write_json(&path, &receipt)?;
    Ok(request.endpoints.participant_role_arn())
}

/// Matching desired state is necessary, not proof that assumption, SSM access,
/// revocation, SCPs, and permission boundaries work. Those are live IAM checks.
pub fn verify_role(api: &dyn AwsApi, request: &ParticipantRequest) -> Result<()> {
    verify_role_state(api, request, false)
}

/// Interrupted destruction may already have removed the owned inline policy or
/// role. Any surviving trust, ownership tags and permissions must still match.
pub(crate) fn verify_removal_role(api: &dyn AwsApi, request: &ParticipantRequest) -> Result<()> {
    verify_role_state(api, request, true)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "participant.verify_role_state")
)]
fn verify_role_state(api: &dyn AwsApi, request: &ParticipantRequest, removing: bool) -> Result<()> {
    request.validate()?;
    let endpoints = &request.endpoints;
    let name = endpoints.participant_role_name();
    let response = match api.call("iam", "get-role", json!({"RoleName":name}), &[]) {
        Err(error)
            if removing
                && crate::removal::missing(&error, &["NoSuchEntity", "NoSuchEntityException"]) =>
        {
            return Ok(());
        }
        result => result?,
    };
    let role = response
        .get("Role")
        .context("participant role response missing")?;
    ensure!(
        role["Arn"] == endpoints.participant_role_arn()
            && role["RoleName"] == name
            && role["Path"] == endpoints.participant_role_path()
            && role["MaxSessionDuration"] == 3600,
        "participant role identity differs from the request"
    );
    ensure!(
        role.get("PermissionsBoundary").is_none(),
        "participant role has an unexpected permissions boundary"
    );
    ensure!(
        canonical_policy(&role["AssumeRolePolicyDocument"])?
            == canonical_policy(&endpoints.participant_trust_policy(&request.trusted_principals)?)?,
        "participant trust differs from the selected principals"
    );
    let tags = role["Tags"]
        .as_array()
        .context("participant role ownership tags missing")?;
    let mut actual = serde_json::Map::new();
    for tag in tags {
        let key = tag["Key"].as_str().context("invalid participant tag")?;
        let value = tag["Value"]
            .as_str()
            .context("invalid participant tag value")?;
        ensure!(
            actual.insert(key.into(), json!(value)).is_none(),
            "duplicate participant ownership tag"
        );
    }
    ensure!(
        Value::Object(actual)
            == ownership_tags(
                &endpoints.scope,
                endpoints.bootstrap_id,
                endpoints.network_id
            ),
        "participant ownership tags differ from request"
    );
    let attached = api.call(
        "iam",
        "list-attached-role-policies",
        json!({"RoleName":name}),
        &[],
    )?;
    ensure!(
        attached.get("IsTruncated").is_none_or(|v| v == false)
            && attached["AttachedPolicies"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "participant role has unexpected attached policies or incomplete inspection"
    );
    let inline = api.call("iam", "list-role-policies", json!({"RoleName":name}), &[])?;
    if removing
        && inline.get("IsTruncated").is_none_or(|v| v == false)
        && inline["PolicyNames"].as_array().is_some_and(Vec::is_empty)
    {
        return Ok(());
    }
    ensure!(
        inline.get("IsTruncated").is_none_or(|v| v == false)
            && inline["PolicyNames"] == json!([POLICY_NAME]),
        "participant role has unexpected inline policies or incomplete inspection"
    );
    let policy = api.call(
        "iam",
        "get-role-policy",
        json!({"RoleName":name,"PolicyName":POLICY_NAME}),
        &[],
    )?;
    ensure!(
        policy["RoleName"] == name && policy["PolicyName"] == POLICY_NAME,
        "participant policy identity differs from request"
    );
    ensure!(
        canonical_policy(&policy["PolicyDocument"])?
            == canonical_policy(&endpoints.participant_policy()?)?,
        "participant permissions differ from fixed-service policy"
    );
    Ok(())
}

/// IAM can return a singleton field as either a scalar or array and can reorder
/// statements/sets. Normalize those representations without dropping conditions
/// or accepting additional principals, actions, resources, or statements.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "participant.canonical_policy")
)]
pub(crate) fn canonical_policy(value: &Value) -> Result<Value> {
    ensure!(
        value.is_object(),
        "IAM policy must be a decoded JSON object"
    );
    fn canonical(value: &Value, field: &str) -> Value {
        match value {
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), canonical(value, key)))
                    .collect(),
            ),
            Value::Array(values) => {
                let mut values: Vec<_> = values.iter().map(|v| canonical(v, "")).collect();
                values.sort_by_cached_key(Value::to_string);
                Value::Array(values)
            }
            Value::String(_)
                if ["Action", "NotAction", "Resource", "NotResource", "AWS"].contains(&field) =>
            {
                json!([value])
            }
            _ => value.clone(),
        }
    }
    let mut normalized = value.clone();
    if normalized.get("Statement").is_some_and(Value::is_object) {
        normalized["Statement"] = json!([normalized["Statement"]]);
    }
    if let Some(statements) = normalized["Statement"].as_array_mut() {
        for statement in statements {
            if let Some(conditions) = statement
                .get_mut("Condition")
                .and_then(Value::as_object_mut)
            {
                for terms in conditions.values_mut().filter_map(Value::as_object_mut) {
                    for value in terms.values_mut() {
                        if !value.is_array() {
                            *value = json!([value]);
                        }
                    }
                }
            }
        }
    }
    Ok(canonical(&normalized, ""))
}

/// Validate all IAM resources in the checkpoint before recovery. A partial
/// owned stack may be incomplete, but must not contain foreign, pending, or
/// retargeted resources. No identity is inferred from AWS tags alone.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "participant.validate_checkpoint")
)]
pub fn validate_checkpoint(request: &ParticipantRequest, export: &Value) -> Result<()> {
    request.validate()?;
    let deployment = export
        .get("deployment")
        .context("participant deployment missing")?;
    ensure!(
        deployment
            .get("pending_operations")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "participant checkpoint has pending operations; resolve them before recovery"
    );
    let empty = Vec::new();
    let resources = match deployment.get("resources") {
        Some(v) => v
            .as_array()
            .context("invalid participant checkpoint resources")?,
        None => &empty,
    };
    let prefix = format!("urn:pulumi:{}::zdn-participant::", request.stack_name());
    let endpoints = &request.endpoints;
    let mut seen = BTreeSet::new();
    for resource in resources {
        let urn = resource["urn"]
            .as_str()
            .context("participant checkpoint resource has no URN")?;
        ensure!(
            urn.starts_with(&prefix) && seen.insert(urn),
            "foreign or duplicate participant checkpoint resource"
        );
        ensure!(
            resource.get("delete").is_none_or(|v| v == false)
                && resource.get("external").is_none_or(|v| v == false),
            "participant checkpoint resource is external or deleting"
        );
        let kind = resource["type"]
            .as_str()
            .context("participant checkpoint resource has no type")?;
        match kind {
            "pulumi:pulumi:Stack" => {
                ensure!(
                    urn == format!(
                        "{prefix}pulumi:pulumi:Stack::zdn-participant-{}",
                        request.stack_name()
                    ),
                    "participant checkpoint root differs from selected stack"
                );
            }
            "pulumi:providers:aws" => {
                ensure!(
                    urn == format!("{prefix}pulumi:providers:aws::provider"),
                    "unexpected participant provider"
                );
                let inputs = &resource["inputs"];
                let accounts = if let Some(encoded) = inputs["allowedAccountIds"].as_str() {
                    serde_json::from_str::<Value>(encoded)
                        .context("invalid participant provider account restriction")?
                } else {
                    inputs["allowedAccountIds"].clone()
                };
                ensure!(
                    inputs["region"] == request.administrator.region
                        && inputs["profile"] == request.administrator.profile
                        && accounts == json!([request.administrator.account_id]),
                    "participant checkpoint provider differs from selected identity"
                );
            }
            "aws:iam/role:Role" => {
                ensure!(
                    urn == format!("{prefix}aws:iam/role:Role::participantRole")
                        && resource["protect"] == true
                        && resource["id"] == endpoints.participant_role_name(),
                    "participant role is not an owned protected resource"
                );
                let inputs = &resource["inputs"];
                ensure!(
                    inputs["name"] == endpoints.participant_role_name()
                        && inputs["path"] == endpoints.participant_role_path()
                        && inputs["maxSessionDuration"] == 3600
                        && inputs.get("permissionsBoundary").is_none_or(Value::is_null)
                        && inputs["tags"]
                            == ownership_tags(
                                &endpoints.scope,
                                endpoints.bootstrap_id,
                                endpoints.network_id
                            ),
                    "participant checkpoint role identity or ownership changed"
                );
                let trust: Value = serde_json::from_str(
                    inputs["assumeRolePolicy"]
                        .as_str()
                        .context("participant checkpoint trust missing")?,
                )?;
                ensure!(
                    canonical_policy(&trust)? == canonical_policy(&legacy_trust(request))?
                        || canonical_policy(&trust)?
                            == canonical_policy(
                                &endpoints.participant_trust_policy(&request.trusted_principals)?
                            )?,
                    "participant checkpoint trust differs from request"
                );
            }
            "aws:iam/rolePolicy:RolePolicy" => {
                ensure!(
                    urn == format!("{prefix}aws:iam/rolePolicy:RolePolicy::participantPolicy")
                        && resource["protect"] == true
                        && resource["id"]
                            == format!("{}:{POLICY_NAME}", endpoints.participant_role_name()),
                    "participant policy is not an owned protected resource"
                );
                let inputs = &resource["inputs"];
                ensure!(
                    inputs["role"] == endpoints.participant_role_name()
                        && inputs["name"] == POLICY_NAME,
                    "participant checkpoint policy identity changed"
                );
                let policy: Value = serde_json::from_str(
                    inputs["policy"]
                        .as_str()
                        .context("participant checkpoint policy missing")?,
                )?;
                ensure!(
                    canonical_policy(&policy)?
                        == canonical_policy(&endpoints.participant_policy()?)?,
                    "participant checkpoint policy differs from request"
                );
            }
            _ => eyre::bail!("unexpected participant checkpoint resource type"),
        }
    }
    Ok(())
}

/// Read the opened descriptor rather than trusting a preceding path check.
/// O_NONBLOCK prevents a swapped FIFO from blocking the CLI before a lock.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "participant.read_regular")
)]
fn read_regular(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_file(),
            "participant input must be a regular file"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path).context("open participant input")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_LOCAL_BYTES as u64,
        "participant input must be a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_LOCAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_LOCAL_BYTES,
        "participant input exceeds its size limit"
    );
    Ok(Some(bytes))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "participant.read_receipt")
)]
fn read_receipt(path: &Path, request: &ParticipantRequest) -> Result<Option<ParticipantReceipt>> {
    let Some(bytes) = read_regular(path)? else {
        return Ok(None);
    };
    let saved: ParticipantReceipt =
        serde_json::from_slice(&bytes).context("invalid participant recovery receipt")?;
    ensure!(
        saved.version == 1 && saved.request == *request,
        "participant request differs from saved recovery receipt"
    );
    saved.request.validate()?;
    ensure!(
        saved.stack_started || (!saved.uncertain && !saved.complete),
        "invalid participant lifecycle receipt"
    );
    Ok(Some(saved))
}

/// Prepare only immutable project bytes before the lifecycle acquires its lock.
/// A concurrent caller can publish the same program, but cannot replace it.
/// Saved request validation precedes even creating the project directory.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "participant.prepare_project")
)]
pub fn prepare_project(request: &ParticipantRequest, directory: &Path) -> Result<PathBuf> {
    let request = request.normalized()?;
    foundation::private_directory(directory)?;
    read_receipt(&directory.join("participant.json"), &request)?;
    // Preserve the immutable v1 program. Accept only the exact previous render
    // for this request, then publish v2 separately. The same owned stack and
    // receipt are reused; checkpoint validation permits only the known upgrade.
    let legacy_project = directory.join("project");
    match fs::symlink_metadata(&legacy_project) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir(),
                "legacy participant project must be a real directory"
            );
            if let Some(bytes) = read_regular(&legacy_project.join("Pulumi.yaml"))? {
                let saved: Value =
                    serde_yaml::from_slice(&bytes).context("invalid legacy participant project")?;
                let mut expected = request.render()?;
                expected["resources"]["participantRole"]["properties"]["assumeRolePolicy"] =
                    json!(legacy_trust(&request).to_string());
                ensure!(
                    saved == expected,
                    "legacy participant project differs from immutable request; it was not overwritten"
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let project = directory.join(PROJECT_DIRECTORY);
    foundation::private_directory(&project)?;
    let bytes = serde_yaml::to_string(&request.render()?)?.into_bytes();
    ensure!(
        bytes.len() <= MAX_LOCAL_BYTES,
        "participant project exceeds its size limit"
    );
    let mut files = vec![("Pulumi.yaml".to_owned(), bytes)];
    // Stack selection does not recover local KMS configuration from the backend.
    // Preserve the existing encrypted key as well as the provider URL on upgrade.
    let config_name = format!("Pulumi.{}.yaml", request.stack_name());
    if let Some(config) = read_regular(&legacy_project.join(&config_name))? {
        files.push((config_name, config));
    }
    for (name, bytes) in files {
        let path = project.join(name);
        let mut temporary = tempfile::NamedTempFile::new_in(&project)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => fs::File::open(&project)?.sync_all()?,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                let saved = read_regular(&path)?
                    .context("participant project disappeared during preparation")?;
                ensure!(
                    saved == bytes,
                    "participant project differs from immutable request; it was not overwritten"
                );
            }
            Err(error) => return Err(error.error.into()),
        }
    }
    Ok(project)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "participant.live_stack")
)]
pub fn live_stack(
    request: &ParticipantRequest,
    directory: &Path,
    managed: &Path,
    cancel: Arc<AtomicBool>,
) -> Result<ParticipantClient<SystemPulumiRunner>> {
    let project = prepare_project(request, directory)?;
    let client = PulumiClient::new(
        PulumiWorkspace {
            tools: ManagedTools::resolve(managed)?,
            work_dir: project,
            diagnostics_dir: directory.join("diagnostics"),
            backend_url: access::admin_backend(&request.team)?,
            secrets_provider: request.team.secrets_provider(),
            aws: AwsContext {
                profile: request.administrator.profile.clone(),
                account_id: request.administrator.account_id.clone(),
                region: request.administrator.region.clone(),
                credential_files: None,
            },
            project: "zdn-participant".into(),
            stack: request.stack_name(),
        },
        SystemPulumiRunner::current_exe()?,
    )?;
    Ok(ParticipantClient { client, cancel })
}
