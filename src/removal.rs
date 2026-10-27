//! Administrator removal. Creation receipts are retained; deletion intent is
//! durable before effects. A missing stack alone is never deletion evidence.

use crate::{
    access,
    access_bootstrap::AccessReceipt,
    aws::{AwsApi, AwsApiError},
    foundation,
    participant::{self, ParticipantReceipt},
    pulumi::{PulumiClient, PulumiRunner, RunControl},
};
use eyre::{bail, ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

mod team;
pub use team::{remove_team, team_plan, TeamRemovalOptions};

/// Fakeable, existing-stack-only boundary. Never refresh before checking saved
/// identities: refresh can silently adopt a replacement with the same name.
pub trait RemovalStack {
    fn checkpoint(&mut self) -> Result<Option<Value>>;
    fn unprotect(&mut self, urns: &[&str]) -> Result<()>;
    fn destroy(&mut self) -> Result<()>;
    fn remove(&mut self) -> Result<()>;
}

pub struct RemovalClient<R> {
    pub client: PulumiClient<R>,
    pub cancel: Arc<AtomicBool>,
}

impl<R: PulumiRunner> RemovalStack for RemovalClient<R> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "removal.removal_client.checkpoint")
    )]
    fn checkpoint(&mut self) -> Result<Option<Value>> {
        let cancel = &self.cancel;
        let mut progress = || {
            Ok(if cancel.load(Ordering::SeqCst) {
                RunControl::Cancel
            } else {
                RunControl::Continue
            })
        };
        if !self.client.stack_exists(&mut progress)? {
            return Ok(None);
        }
        self.client.prepare_stack(false, &mut progress)?;
        Ok(Some(
            if self.client.workspace.project == "zdn-participant" {
                self.client.participant_export(&mut progress)?
            } else {
                self.client.access_export(&mut progress)?
            },
        ))
    }
    fn unprotect(&mut self, urns: &[&str]) -> Result<()> {
        let cancel = &self.cancel;
        self.client.unprotect(urns, &mut || active(cancel))
    }
    fn destroy(&mut self) -> Result<()> {
        let cancel = &self.cancel;
        self.client.destroy(&mut || active(cancel))
    }
    fn remove(&mut self) -> Result<()> {
        let cancel = &self.cancel;
        self.client.remove_stack(&mut || active(cancel))
    }
}

fn active(cancel: &AtomicBool) -> Result<RunControl> {
    Ok(if cancel.load(Ordering::SeqCst) {
        RunControl::Cancel
    } else {
        RunControl::Continue
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StackRemovalReceipt {
    pub version: u32,
    pub creation: Value,
    /// Null only for an unstarted participant, after independent stack and role
    /// absence. Such a receipt grants no resource deletion authority.
    pub checkpoint: Value,
    pub uncertain: bool,
    pub stack_removed: bool,
    /// Live GetDocument denial for every fixed service from a still-valid old
    /// participant session. Not proof of STS invalidation or StartSession denial.
    pub revocation_verified: bool,
}

pub(crate) struct Lock(fs::File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.lock")
)]
pub(crate) fn lock(path: &Path) -> Result<Lock> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "removal lock must be a regular file"
    );
    file.try_lock_exclusive()
        .context("another lifecycle operation holds the local lock")?;
    Ok(Lock(file))
}

pub(crate) fn missing(error: &eyre::Report, codes: &[&str]) -> bool {
    error
        .downcast_ref::<AwsApiError>()
        .is_some_and(|e| codes.contains(&e.code.as_str()))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.resources")
)]
pub(crate) fn resources(checkpoint: &Value) -> Result<&[Value]> {
    let deployment = checkpoint
        .get("deployment")
        .context("removal checkpoint has no deployment")?;
    ensure!(
        deployment
            .get("pending_operations")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "removal refuses pending Pulumi operations; resolve them separately"
    );
    let list = deployment
        .get("resources")
        .map(|v| v.as_array().context("invalid removal resources"))
        .transpose()?;
    let list = list.map(Vec::as_slice).unwrap_or_default();
    let mut seen = BTreeSet::new();
    for resource in list {
        ensure!(
            seen.insert(resource["urn"].as_str().context("resource URN missing")?),
            "duplicate removal resource"
        );
        ensure!(
            [
                "external",
                "delete",
                "pendingReplacement",
                "imported",
                "retainOnDelete"
            ]
            .iter()
            .all(|key| resource.get(key).is_none_or(|v| v == false))
                && ["importID", "importId"]
                    .iter()
                    .all(|key| resource.get(key).is_none_or(|v| v == "")),
            "removal refuses external, imported, retained or pending resources"
        );
    }
    Ok(list)
}

fn aws_resources(checkpoint: &Value) -> Result<Vec<&Value>> {
    Ok(resources(checkpoint)?
        .iter()
        .filter(|r| r["type"].as_str().is_some_and(|t| t.starts_with("aws:")))
        .collect())
}

/// On recovery only deletions and protection changes are permitted. Identity,
/// inputs and immutable provider outputs remain pinned to the original plan.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.validate_remaining")
)]
fn validate_remaining(original: &Value, current: &Value) -> Result<()> {
    let original = resources(original)?;
    for resource in resources(current)? {
        let saved = original
            .iter()
            .find(|r| r["urn"] == resource["urn"])
            .context("new resource appeared during removal")?;
        for key in [
            "type",
            "id",
            "inputs",
            "provider",
            "custom",
            "parent",
            "dependencies",
            "propertyDependencies",
            "deletedWith",
            "aliases",
            "ignoreChanges",
            "replaceOnChanges",
            "additionalSecretOutputs",
        ] {
            ensure!(
                resource.get(key) == saved.get(key),
                "resource identity or inputs changed during removal"
            );
        }
        for key in ["uniqueId", "policyId", "arn", "createdAt"] {
            ensure!(
                resource["outputs"].get(key) == saved["outputs"].get(key),
                "resource incarnation changed during removal"
            );
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.participant_plan")
)]
pub fn participant_plan(directory: &Path) -> Result<Value> {
    let receipt: ParticipantReceipt = foundation::read_json(&directory.join("participant.json"))?;
    receipt.request.validate()?;
    ensure!(
        receipt.version == 1
            && (receipt.stack_started || (!receipt.uncertain && !receipt.complete)),
        "no participant creation ownership receipt"
    );
    if !receipt.stack_started {
        return Ok(
            json!({"kind":"participant-removal", "roleArn":receipt.request.endpoints.participant_role_arn(),
            "stack":receipt.request.stack_name(),"cloudChanges":false,"liveOwnershipChecked":false,
            "actions":["independently observe role and stack absence; refuse any existing role or stack", "record unstarted grant closure without deleting resources"],
            "revocation":"No original RoleId or grant exists in this receipt; revocation cannot be qualified."}),
        );
    }
    Ok(
        json!({"kind":"participant-removal", "roleArn":receipt.request.endpoints.participant_role_arn(),
        "stack":receipt.request.stack_name(),"cloudChanges":false,"liveOwnershipChecked":false,
        "actions":["validate original receipt, checkpoint and live immutable IAM identity", "refuse active SSM sessions", "unprotect exact owned resources", "destroy and observe IAM absence", "remove empty stack"],
        "revocation":"Role deletion does not prove STS invalidation. --revocation-profile tests read-only GetDocument denial for every fixed service with still-valid old credentials; StartSession is not probed. Without this evidence revocation remains pending."}),
    )
}

/// Remove a separate participant grant without requiring live network documents
/// (networks can already be destroyed). No participant identity is reconstructed
/// from an imported endpoint file or from AWS tags.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.remove_participant")
)]
pub fn remove_participant(
    api: &dyn AwsApi,
    directory: &Path,
    stack: &mut dyn RemovalStack,
    reconcile: bool,
    revocation: Option<&dyn AwsApi>,
) -> Result<Value> {
    let _lock = lock(&directory.join("participant.lock"))?;
    let creation: ParticipantReceipt = foundation::read_json(&directory.join("participant.json"))?;
    creation.request.validate()?;
    ensure!(
        creation.version == 1
            && (creation.stack_started || (!creation.uncertain && !creation.complete)),
        "no participant creation ownership receipt"
    );
    ensure!(
        !creation.uncertain || reconcile,
        "participant setup outcome uncertain; inspect and use --reconcile"
    );
    let request = &creation.request;
    crate::aws::verify_identity(api, &request.administrator)?;
    no_sessions(api, &request.endpoints)?;
    let path = directory.join("removal.json");
    let current = stack.checkpoint()?;
    if !creation.stack_started {
        // A preflight receipt owns nothing. Never adopt a stack, fabricate a
        // checkpoint, or delete a same-name role based on this intent alone.
        ensure!(
            current.is_none(),
            "unstarted participant stack exists; recover its original ownership receipt"
        );
        ensure!(
            revocation.is_none(),
            "unstarted participant has no original RoleId for revocation verification"
        );
        require_absent(
            api,
            "iam",
            "get-role",
            json!({"RoleName":request.endpoints.participant_role_name()}),
            &["NoSuchEntity", "NoSuchEntityException"],
        )?;
        let receipt = StackRemovalReceipt {
            version: 1,
            creation: serde_json::to_value(&creation)?,
            checkpoint: Value::Null,
            uncertain: false,
            stack_removed: true,
            revocation_verified: false,
        };
        if path.try_exists()? {
            let saved: StackRemovalReceipt = foundation::read_json(&path)?;
            ensure!(
                serde_json::to_value(&saved)? == serde_json::to_value(&receipt)?,
                "unstarted participant closure evidence changed"
            );
        } else {
            foundation::write_json(&path, &receipt)?;
        }
        return Ok(json!({"roleArn":request.endpoints.participant_role_arn(),
            "stackRemoved":true,"roleAbsent":true,"activeSessionsAbsent":true,
            "revocationVerified":false,"status":"not-started","receipt":path}));
    }
    if !path.try_exists()? {
        crate::aws::verify_backend_for_cleanup(api, &request.administrator, &request.team)?;
        participant::verify_role(api, request)?;
    }
    let mut receipt = open_stack_receipt(
        &path,
        &serde_json::to_value(&creation)?,
        current.as_ref(),
        reconcile,
        |checkpoint| {
            participant::validate_checkpoint(request, checkpoint)?;
            let role = aws_resources(checkpoint)?
                .into_iter()
                .find(|r| r["type"] == "aws:iam/role:Role")
                .context("participant checkpoint has no owned role")?;
            ensure!(
                role["custom"] == true,
                "participant role is not a custom resource"
            );
            Ok(())
        },
    )?;
    // Read every original identity, including resources already removed from the
    // current checkpoint. This prevents an orphan/replacement becoming success.
    for role in aws_resources(&receipt.checkpoint)?
        .into_iter()
        .filter(|r| r["type"] == "aws:iam/role:Role")
    {
        immutable_role(api, role, true)?;
    }
    participant::verify_removal_role(api, request)?;
    teardown_stack(&path, &mut receipt, current.as_ref(), stack, |_| {
        require_absent(
            api,
            "iam",
            "get-role",
            json!({"RoleName":request.endpoints.participant_role_name()}),
            &["NoSuchEntity", "NoSuchEntityException"],
        )?;
        no_sessions(api, &request.endpoints)
    })?;
    require_absent(
        api,
        "iam",
        "get-role",
        json!({"RoleName":request.endpoints.participant_role_name()}),
        &["NoSuchEntity", "NoSuchEntityException"],
    )?;
    no_sessions(api, &request.endpoints)?;
    if let Some(probe) = revocation {
        verify_revocation(probe, &creation, &receipt.checkpoint)?;
        receipt.revocation_verified = true;
    }
    receipt.uncertain = false;
    foundation::write_json(&path, &receipt)?;
    Ok(
        json!({"roleArn":request.endpoints.participant_role_arn(),"stackRemoved":receipt.stack_removed,
        "roleAbsent":true,"activeSessionsAbsent":true,"revocationVerified":receipt.revocation_verified,
        "revocationScope":"ssm:GetDocument on every fixed service using still-valid old credentials; not STS invalidation or StartSession qualification",
        "status":if receipt.revocation_verified {"removed"} else {"revocation-pending"},"receipt":path}),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.open_stack_receipt")
)]
fn open_stack_receipt(
    path: &Path,
    creation: &Value,
    current: Option<&Value>,
    reconcile: bool,
    validate: impl FnOnce(&Value) -> Result<()>,
) -> Result<StackRemovalReceipt> {
    if path.try_exists()? {
        let saved: StackRemovalReceipt = foundation::read_json(path)?;
        ensure!(
            saved.version == 1 && saved.creation == *creation,
            "creation receipt changed since removal began"
        );
        ensure!(
            !saved.uncertain || reconcile,
            "removal outcome uncertain; inspect and use --reconcile"
        );
        validate(&saved.checkpoint)?;
        if let Some(current) = current {
            ensure!(!saved.stack_removed, "removed stack reappeared");
            validate_remaining(&saved.checkpoint, current)?;
        }
        return Ok(saved);
    }
    let checkpoint = current
        .context("stack missing without a removal receipt; refusing to fabricate success")?;
    validate(checkpoint)?;
    let receipt = StackRemovalReceipt {
        version: 1,
        creation: creation.clone(),
        checkpoint: checkpoint.clone(),
        uncertain: true,
        stack_removed: false,
        revocation_verified: false,
    };
    foundation::write_json(path, &receipt)?;
    Ok(receipt)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.teardown_stack")
)]
fn teardown_stack(
    path: &Path,
    receipt: &mut StackRemovalReceipt,
    current: Option<&Value>,
    stack: &mut dyn RemovalStack,
    mut verify_absent: impl FnMut(&Value) -> Result<()>,
) -> Result<()> {
    receipt.uncertain = true;
    foundation::write_json(path, receipt)?;
    if let Some(checkpoint) = current {
        let urns = aws_resources(checkpoint)?
            .into_iter()
            .filter(|resource| resource["protect"] == true)
            .map(|resource| resource["urn"].as_str().context("resource URN missing"))
            .collect::<Result<Vec<_>>>()?;
        if !urns.is_empty() {
            stack.unprotect(&urns)?;
        }
        stack.destroy()?;
        let after = stack
            .checkpoint()?
            .context("stack vanished during destroy")?;
        validate_remaining(&receipt.checkpoint, &after)?;
        ensure!(
            aws_resources(&after)?.is_empty(),
            "destroy left managed resources in the checkpoint"
        );
        verify_absent(&receipt.checkpoint)?;
        stack.remove()?;
    } else {
        verify_absent(&receipt.checkpoint)?;
    }
    ensure!(
        stack.checkpoint()?.is_none(),
        "stack removal has not been observed"
    );
    receipt.stack_removed = true;
    foundation::write_json(path, receipt)
}

pub(crate) fn require_absent(
    api: &dyn AwsApi,
    service: &str,
    operation: &str,
    input: Value,
    codes: &[&str],
) -> Result<()> {
    match api.call(service, operation, input, &[]) {
        Err(error) if missing(&error, codes) => Ok(()),
        Err(error) => Err(error),
        Ok(_) => bail!("{service} {operation} still observes a resource; removal is not complete"),
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.immutable_role")
)]
fn immutable_role(api: &dyn AwsApi, resource: &Value, allow_missing: bool) -> Result<()> {
    let name = resource["id"]
        .as_str()
        .context("role checkpoint has no name")?;
    let saved = resource["outputs"]["uniqueId"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("role checkpoint lacks immutable RoleId")?;
    let value = match api.call("iam", "get-role", json!({"RoleName":name}), &[]) {
        Err(error)
            if allow_missing && missing(&error, &["NoSuchEntity", "NoSuchEntityException"]) =>
        {
            return Ok(());
        }
        other => other?,
    };
    ensure!(
        value["Role"]["RoleId"] == saved
            && value["Role"]["Arn"] == resource["outputs"]["arn"]
            && value["Role"]["Path"] == resource["inputs"]["path"],
        "live role incarnation differs from original checkpoint"
    );
    let profiles = api.call(
        "iam",
        "list-instance-profiles-for-role",
        json!({"RoleName":name}),
        &[],
    )?;
    ensure!(
        profiles.get("IsTruncated").is_none_or(|v| v == false)
            && profiles["InstanceProfiles"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "role has instance-profile consumers"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.no_sessions")
)]
fn no_sessions(api: &dyn AwsApi, endpoints: &crate::endpoints::EndpointFile) -> Result<()> {
    let targets: BTreeSet<_> = endpoints.targets.iter().map(|t| &t.instance_id).collect();
    for target in targets {
        let value = api.call(
            "ssm",
            "describe-sessions",
            json!({"State":"Active","Filters":[{"key":"Target","value":target}]}),
            &[],
        )?;
        ensure!(
            value.get("NextToken").is_none_or(|v| v == "")
                && value["Sessions"].as_array().is_some_and(Vec::is_empty),
            "active SSM sessions or incomplete inspection; close sessions before removing grants"
        );
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.verify_revocation")
)]
fn verify_revocation(
    api: &dyn AwsApi,
    creation: &ParticipantReceipt,
    checkpoint: &Value,
) -> Result<()> {
    let request = &creation.request;
    let identity = crate::aws::verify_identity(api, &request.administrator)?;
    let prefix = format!(
        "arn:aws:sts::{}:assumed-role/{}/",
        request.team.aws.account_id,
        request.endpoints.participant_role_name()
    );
    let session = identity.arn.strip_prefix(&prefix).context(
        "revocation profile must contain still-valid cached credentials for this participant role",
    )?;
    let role = aws_resources(checkpoint)?
        .into_iter()
        .find(|r| r["type"] == "aws:iam/role:Role")
        .context("participant checkpoint has no role")?;
    let role_id = role["outputs"]["uniqueId"]
        .as_str()
        .context("participant RoleId missing")?;
    ensure!(
        identity.user_id == format!("{role_id}:{session}"),
        "revocation credentials belong to another role incarnation"
    );
    ensure!(
        request
            .endpoints
            .participant_session_names(&request.trusted_principals)?
            .values()
            .any(|v| v == session),
        "revocation profile has an unrecognized participant session name"
    );
    for target in &request.endpoints.targets {
        let input =
            json!({"Name":request.endpoints.document_arn(target.service),"DocumentFormat":"JSON"});
        match api.call("ssm", "get-document", input, &[]) {
            Err(error) if missing(&error, &["AccessDenied", "AccessDeniedException"]) => {}
            Err(error) => {
                return Err(error).context(
                    "live revocation is unproven; only an authorization denial qualifies",
                );
            }
            Ok(_) => {
                bail!("old participant credentials still authorize GetDocument; revocation failed")
            }
        }
    }
    Ok(())
}

/// Validate the entire administrator checkpoint, not just its boundary policy.
/// Interpolations resolve from deterministic owned identities, never untrusted
/// checkpoint outputs. Unknown resource kinds/names are not cleanup authority.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.validate_access_checkpoint")
)]
pub fn validate_access_checkpoint(creation: &AccessReceipt, checkpoint: &Value) -> Result<()> {
    creation.request.validate()?;
    let selected = creation
        .selected_access
        .as_ref()
        .context("administrator receipt has no selected identities; finish setup before removal")?;
    let program = creation.request.render_with_access(selected)?;
    let expected = program["resources"]
        .as_object()
        .context("administrator resources missing")?;
    let stack = format!("zdn-{}", creation.request.team.bootstrap_id.simple());
    let prefix = format!("urn:pulumi:{stack}::zdn-access::");
    let mut identities = BTreeMap::new();
    for (name, resource) in expected {
        let properties = &resource["properties"];
        if let Some(value) = properties["name"]
            .as_str()
            .or(properties["bucket"].as_str())
        {
            identities.insert(format!("{name}.name"), value.to_owned());
            identities.insert(format!("{name}.id"), value.to_owned());
            let arn = match resource["type"].as_str() {
                Some("aws:iam:Role") => format!(
                    "arn:aws:iam::{}:role{}{value}",
                    creation.request.team.aws.account_id,
                    properties["path"].as_str().unwrap()
                ),
                Some("aws:iam:Policy") => format!(
                    "arn:aws:iam::{}:policy{}{value}",
                    creation.request.team.aws.account_id,
                    properties["path"].as_str().unwrap()
                ),
                _ => String::new(),
            };
            if !arn.is_empty() {
                identities.insert(format!("{name}.arn"), arn);
            }
        }
    }
    let mut names = BTreeSet::new();
    for resource in resources(checkpoint)? {
        let urn = resource["urn"].as_str().context("resource URN missing")?;
        let suffix = urn
            .strip_prefix(&prefix)
            .context("foreign administrator stack")?;
        let (kind, name) = suffix
            .split_once("::")
            .context("invalid administrator URN")?;
        if kind == "pulumi:pulumi:Stack" {
            ensure!(
                name == format!("zdn-access-{stack}"),
                "foreign administrator root"
            );
            continue;
        }
        let expected = expected
            .get(name)
            .context("unknown administrator resource")?;
        ensure!(
            names.insert(name),
            "duplicate administrator logical resource"
        );
        ensure!(
            resource["type"] == kind
                && kind
                    == canonical_type(expected["type"].as_str().context("resource type missing")?)?,
            "administrator resource type changed"
        );
        if kind.starts_with("aws:") {
            ensure!(
                resource["custom"] == true && resource["protect"] == true,
                "administrator resource is not owned and protected"
            );
        }
        for (key, value) in expected["properties"]
            .as_object()
            .context("resource properties missing")?
        {
            let wanted = resolve(value, &identities)?;
            let actual = &resource["inputs"][key];
            let actual = if key == "allowedAccountIds" && actual.is_string() {
                serde_json::from_str(actual.as_str().unwrap())?
            } else {
                actual.clone()
            };
            ensure!(
                equivalent(&actual, &wanted)?,
                "administrator checkpoint property changed: {name}.{key}"
            );
        }
        let inputs = &resource["inputs"];
        let id = resource["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .context("administrator resource ID missing")?;
        match kind {
            "aws:iam/role:Role" => ensure!(
                inputs["name"] == id
                    && identities
                        .get(&format!("{name}.arn"))
                        .is_some_and(|arn| resource["outputs"]["arn"] == *arn),
                "role ID or ARN changed"
            ),
            "aws:iam/policy:Policy" => ensure!(
                identities
                    .get(&format!("{name}.arn"))
                    .is_some_and(|v| v == id),
                "policy ID changed"
            ),
            "aws:iam/rolePolicy:RolePolicy" => ensure!(
                id == format!(
                    "{}:{}",
                    inputs["role"].as_str().unwrap_or_default(),
                    inputs["name"].as_str().unwrap_or_default()
                ),
                "inline policy ID changed"
            ),
            "aws:iam/rolePolicyAttachment:RolePolicyAttachment" => {
                // Provider-generated attachment IDs include a suffix. Live
                // consumers and exact role/policy inputs are checked separately.
                ensure!(
                    id.starts_with(inputs["role"].as_str().context("attachment role missing")?),
                    "attachment ID changed"
                );
            }
            "aws:codebuild/project:Project" => ensure!(
                id == format!(
                    "arn:aws:codebuild:{}:{}:project/{}",
                    creation.request.team.aws.region,
                    creation.request.team.aws.account_id,
                    inputs["name"]
                        .as_str()
                        .context("build project name missing")?
                ),
                "build project ARN changed"
            ),
            "pulumi:providers:aws" => {}
            _ => {
                let expected_id = inputs["bucket"]
                    .as_str()
                    .or(inputs["name"].as_str())
                    .context("resource identity missing")?;
                ensure!(id == expected_id, "build resource ID changed");
            }
        }
    }
    ensure!(
        names.len() == expected.len(),
        "completed administrator checkpoint is incomplete; recover its original checkpoint"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.canonical_type")
)]
fn canonical_type(kind: &str) -> Result<&str> {
    Ok(match kind {
        "pulumi:providers:aws" => kind,
        "aws:iam:Role" => "aws:iam/role:Role",
        "aws:iam:Policy" => "aws:iam/policy:Policy",
        "aws:iam:RolePolicy" => "aws:iam/rolePolicy:RolePolicy",
        "aws:iam:RolePolicyAttachment" => "aws:iam/rolePolicyAttachment:RolePolicyAttachment",
        "aws:s3:BucketV2" => "aws:s3/bucketV2:BucketV2",
        "aws:s3:BucketPublicAccessBlock" => {
            "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock"
        }
        "aws:s3:BucketOwnershipControls" => {
            "aws:s3/bucketOwnershipControls:BucketOwnershipControls"
        }
        "aws:s3:BucketServerSideEncryptionConfigurationV2" => {
            "aws:s3/bucketServerSideEncryptionConfigurationV2:BucketServerSideEncryptionConfigurationV2"
        }
        "aws:s3:BucketVersioningV2" => "aws:s3/bucketVersioningV2:BucketVersioningV2",
        "aws:s3:BucketPolicy" => "aws:s3/bucketPolicy:BucketPolicy",
        "aws:ecr:Repository" => "aws:ecr/repository:Repository",
        "aws:cloudwatch:LogGroup" => "aws:cloudwatch/logGroup:LogGroup",
        "aws:codebuild:Project" => "aws:codebuild/project:Project",
        _ => bail!("unsupported administrator resource type"),
    })
}

fn resolve(value: &Value, identities: &BTreeMap<String, String>) -> Result<Value> {
    Ok(match value {
        Value::String(value) => {
            let mut output = value.clone();
            for (key, value) in identities {
                output = output.replace(&format!("${{{key}}}"), value);
            }
            // Escaped IAM variables are literal, not Pulumi references.
            output = output.replace("$${", "${");
            Value::String(output)
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|v| resolve(v, identities))
                .collect::<Result<_>>()?,
        ),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(k, v)| Ok((k.clone(), resolve(v, identities)?)))
                .collect::<Result<_>>()?,
        ),
        other => other.clone(),
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.equivalent")
)]
fn equivalent(actual: &Value, expected: &Value) -> Result<bool> {
    if actual == expected {
        return Ok(true);
    }
    if let (Some(a), Some(e)) = (actual.as_str(), expected.as_str()) {
        if let (Ok(a), Ok(e)) = (
            serde_json::from_str::<Value>(a),
            serde_json::from_str::<Value>(e),
        ) {
            return Ok(participant::canonical_policy(&a)? == participant::canonical_policy(&e)?);
        }
    }
    // The pinned provider persists empty bookkeeping inside nested properties.
    // Strip only that metadata, preserving all values and array ordering.
    fn strip_empty_defaults(value: &mut Value) {
        match value {
            Value::Object(fields) => {
                if fields
                    .get("__defaults")
                    .is_some_and(|v| v.as_array().is_some_and(Vec::is_empty))
                {
                    fields.remove("__defaults");
                }
                fields.values_mut().for_each(strip_empty_defaults);
            }
            Value::Array(values) => values.iter_mut().for_each(strip_empty_defaults),
            _ => {}
        }
    }
    let mut actual = actual.clone();
    strip_empty_defaults(&mut actual);
    Ok(actual == *expected)
}
