//! Administrator-only shared IAM lifecycle. Network teardown never calls this.

use crate::{
    access::{self, AccessRequest, DeploymentAccess, RoleManagement},
    aws::{self, AwsApi, TeamDefinition},
    foundation,
    foundation_live::Runtime,
    pulumi::{
        AwsContext, ManagedTools, PulumiClient, PulumiRunner, PulumiWorkspace, RunControl,
        SystemPulumiRunner,
    },
};
use eyre::{ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

/// Boundary for testing ordering and recovery without AWS or Pulumi processes.
pub trait AccessStack {
    fn exists(&mut self) -> Result<bool>;
    fn prepare(&mut self, create: bool) -> Result<()>;
    fn refresh(&mut self) -> Result<()>;
    fn configure(
        &mut self,
        request: &AccessRequest,
        saved: Option<&DeploymentAccess>,
    ) -> Result<DeploymentAccess>;
    fn apply(&mut self) -> Result<()>;
    fn outputs(&mut self) -> Result<Value>;
}

pub struct AccessClient<R> {
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
impl<R: PulumiRunner> AccessStack for AccessClient<R> {
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
        tracing::instrument(skip_all, name = "access_bootstrap.access_client.configure")
    )]
    fn configure(
        &mut self,
        request: &AccessRequest,
        saved: Option<&DeploymentAccess>,
    ) -> Result<DeploymentAccess> {
        request.validate()?;
        let workspace = &self.client.workspace;
        ensure!(
            workspace.project == "zdn-access"
                && workspace.stack == format!("zdn-{}", request.team.bootstrap_id.simple())
                && workspace.backend_url == access::admin_backend(&request.team)?
                && workspace.secrets_provider == request.team.secrets_provider()
                && workspace.aws.profile == request.administrator.profile
                && workspace.aws.account_id == request.administrator.account_id
                && workspace.aws.region == request.administrator.region,
            "administrator recovery request differs from the selected stack"
        );
        let export = self.client.access_export(&mut || control(&self.cancel))?;
        let access = recovery_access(request, saved, &export)?;
        let program = request.render_with_access(&access)?;
        let previous: Value = serde_yaml::from_slice(&fs::read(
            self.client.workspace.work_dir.join("Pulumi.yaml"),
        )?)
        .map_err(|_| eyre::eyre!("invalid prepared administrator project"))?;
        // Prepare validated the provider and cached its defaults. Recovery may
        // change policy names, never that provider selection. Apply previews
        // this final program and binds its hash into the saved plan.
        ensure!(
            previous.pointer("/resources/provider") == program.pointer("/resources/provider"),
            "recovery provider differs from the prepared administrator project"
        );
        foundation::write_private(
            &self.client.workspace.work_dir.join("Pulumi.yaml"),
            serde_yaml::to_string(&program)?.as_bytes(),
        )?;
        Ok(access)
    }
    fn apply(&mut self) -> Result<()> {
        self.client.preview(&mut || control(&self.cancel))?;
        self.client.up(&mut || control(&self.cancel))
    }
    fn outputs(&mut self) -> Result<Value> {
        self.client.access_outputs(&mut || control(&self.cancel))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessReceipt {
    pub version: u32,
    pub request: AccessRequest,
    pub stack_started: bool,
    pub uncertain: bool,
    pub complete: bool,
    /// Chosen before apply, so retries cannot switch a recovered boundary ARN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_access: Option<DeploymentAccess>,
}

/// Infer the old creation order only from an owned Pulumi checkpoint. Keep the
/// winning policy's name, ARN and purpose; never rename or repurpose a boundary.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "access_bootstrap.recovery_access")
)]
fn recovery_access(
    request: &AccessRequest,
    saved: Option<&DeploymentAccess>,
    export: &Value,
) -> Result<DeploymentAccess> {
    request.validate()?;
    ensure!(
        request.existing.is_none(),
        "external roles have no managed stack"
    );
    let deployment = export
        .get("deployment")
        .context("missing administrator deployment")?;
    if let Some(pending) = deployment.get("pending_operations") {
        ensure!(
            pending.as_array().is_some_and(Vec::is_empty),
            "administrator stack has pending operations; resolve them before choosing recovery names"
        );
    }
    let empty = Vec::new();
    let resources = match deployment.get("resources") {
        Some(value) => value
            .as_array()
            .context("invalid administrator resources")?,
        None => &empty,
    };
    let find = |name: &str| -> Result<Option<&Value>> {
        let suffix = format!("::{name}");
        let matches: Vec<_> = resources
            .iter()
            .filter(|resource| {
                resource
                    .get("urn")
                    .and_then(Value::as_str)
                    .is_some_and(|urn| urn.ends_with(&suffix))
            })
            .collect();
        ensure!(
            matches.len() <= 1,
            "duplicate administrator policy in checkpoint"
        );
        if let Some(resource) = matches.first() {
            let urn = format!(
                "urn:pulumi:zdn-{}::zdn-access::aws:iam/policy:Policy::{name}",
                request.team.bootstrap_id.simple()
            );
            ensure!(
                resource["urn"] == urn
                    && resource["type"] == "aws:iam/policy:Policy"
                    && resource.get("delete").is_none_or(|v| v == false)
                    && resource.get("external").is_none_or(|v| v == false)
                    && resource["protect"] == true,
                "administrator policy is not an owned protected resource"
            );
        }
        Ok(matches.first().copied())
    };
    let current = DeploymentAccess::managed(&request.team);
    let legacy = DeploymentAccess::legacy_managed(&request.team);
    let boundary = find("runtimeBoundary")?;
    let detected = match boundary {
        Some(resource) if resource["id"] == legacy.runtime_boundary_arn => legacy.clone(),
        _ => current.clone(),
    };
    let selected = saved
        .cloned()
        .or_else(|| request.team.deployment.clone())
        .unwrap_or(detected);
    selected.validate(&request.team)?;
    ensure!(
        selected.management == RoleManagement::Zdn,
        "recovery needs managed deployment access"
    );
    ensure!(
        request
            .team
            .deployment
            .as_ref()
            .is_none_or(|access| *access == selected),
        "setup cannot retarget existing deployment access"
    );
    let check_identity = |resource: &Value, arn: &str| -> Result<()> {
        let inputs = resource
            .get("inputs")
            .context("administrator policy has no saved inputs")?;
        ensure!(
            resource["id"] == arn
                && inputs["name"] == arn.rsplit('/').next().unwrap()
                && inputs["path"] == access::admin_path(&request.team)
                && inputs["tags"] == access::admin_tags(&request.team),
            "administrator policy identity or ownership differs from the recovery receipt"
        );
        Ok(())
    };
    if let Some(boundary) = boundary {
        check_identity(boundary, &selected.runtime_boundary_arn)?;
        // A legacy name is accepted only for the original restrictive boundary,
        // never for the management policy that competed for the same name.
        if selected == legacy {
            let document: Value = serde_json::from_str(
                boundary
                    .pointer("/inputs/policy")
                    .and_then(Value::as_str)
                    .context("missing legacy boundary policy")?,
            )
            .map_err(|_| eyre::eyre!("invalid legacy boundary policy"))?;
            ensure!(
                document == access::runtime_boundary()
                    || document == access::runtime_boundary_for_team(&request.team)?,
                "legacy policy is not the expected runtime boundary"
            );
        }
    }
    if let Some(policy) = find("runtimePolicy")? {
        check_identity(policy, &selected.policy_arn(&request.team, "runtime"))?;
    }
    Ok(selected)
}

/// IAM grants can lag a successful administrator apply. Only this final setup
/// check retries authorization errors; ordinary backend checks remain fail-fast.
pub fn verify_developer_backend(
    api: &dyn AwsApi,
    selection: &aws::AwsSelection,
    team: &TeamDefinition,
    runtime: &dyn Runtime,
    cancel: &AtomicBool,
) -> Result<()> {
    wait_for_permissions(
        || aws::verify_backend(api, selection, team),
        runtime,
        cancel,
    )
}

fn verification_active(cancel: &AtomicBool) -> Result<()> {
    ensure!(
        !cancel.load(Ordering::SeqCst),
        "developer backend verification cancelled; IAM setup remains saved"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "access_bootstrap.wait_for_permissions")
)]
fn wait_for_permissions(
    mut verify: impl FnMut() -> Result<()>,
    runtime: &dyn Runtime,
    cancel: &AtomicBool,
) -> Result<()> {
    let deadline = runtime.monotonic() + Duration::from_secs(60);
    let mut delay = Duration::from_secs(1);
    let mut waiting = false;
    loop {
        verification_active(cancel)?;
        let result = verify();
        verification_active(cancel)?;
        let error = match result {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        if !error
            .downcast_ref::<aws::AwsApiError>()
            .is_some_and(|error| {
                matches!(
                    error.code.as_str(),
                    "403" | "AccessDenied" | "AccessDeniedException"
                )
            })
        {
            return Err(error);
        }
        if !waiting {
            eprintln!("zdn: waiting for new IAM permissions to reach the developer backend checks");
            waiting = true;
        }
        let next_attempt = (runtime.monotonic() + delay).min(deadline);
        while runtime.monotonic() < next_attempt {
            verification_active(cancel)?;
            runtime.sleep(
                next_attempt
                    .saturating_sub(runtime.monotonic())
                    .min(Duration::from_millis(500)),
            );
        }
        verification_active(cancel)?;
        // The retry window includes API execution. A request already in flight
        // keeps its own AWS CLI timeout, but cannot start another retry at 60s.
        if runtime.monotonic() >= deadline {
            return Err(error).context(
                "new IAM permissions did not become available within the 60-second retry window",
            );
        }
        delay = (delay * 2).min(Duration::from_secs(15));
    }
}

// Unlock explicitly: a concurrent process spawn can briefly inherit the open
// file description before exec. Closing only our descriptor would leave the
// lock held until that inherited descriptor closes.
struct AccessLock(fs::File);
impl Drop for AccessLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

/// Save before effects and reuse deterministic names. An uncertain apply needs
/// explicit reconciliation; neither a failed selection nor a foreign stack is
/// treated as permission to create another role.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "access_bootstrap.provision")
)]
pub fn provision(
    api: &dyn AwsApi,
    request: &AccessRequest,
    directory: &Path,
    stack: &mut dyn AccessStack,
    reconcile: bool,
) -> Result<TeamDefinition> {
    request.validate()?;
    foundation::private_directory(directory)?;
    let lock_path = directory.join("access.lock");
    if let Ok(meta) = fs::symlink_metadata(&lock_path) {
        ensure!(
            meta.file_type().is_file(),
            "access lock must be a regular file"
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
        .context("another administrator setup holds the local lock")?;
    let _lock = AccessLock(lock);
    ensure!(
        !directory.join("removal.json").try_exists()?,
        "administrator removal has begun; setup cannot recreate grants"
    );
    let receipt_path = directory.join("access.json");
    let mut receipt = if receipt_path.exists() {
        let saved: AccessReceipt = foundation::read_json(&receipt_path)?;
        ensure!(
            saved.version == 1 && saved.request == *request,
            "administrator request differs from saved recovery receipt"
        );
        saved
    } else {
        let saved = AccessReceipt {
            version: 1,
            request: request.clone(),
            stack_started: false,
            uncertain: false,
            complete: false,
            selected_access: None,
        };
        foundation::write_json(&receipt_path, &saved)?;
        saved
    };
    if let Some(selected) = &receipt.selected_access {
        selected.validate(&request.team)?;
        ensure!(
            request.existing.is_none() && selected.management == RoleManagement::Zdn,
            "invalid managed recovery identity in administrator receipt"
        );
        ensure!(
            request
                .team
                .deployment
                .as_ref()
                .is_none_or(|access| access == selected),
            "setup cannot retarget existing deployment access"
        );
    }
    ensure!(
        !receipt.uncertain || reconcile,
        "administrator apply has an uncertain outcome; inspect the stack and retry with --reconcile"
    );
    // This read-only check must pass before any IAM stack operation. S3/KMS are
    // bootstrapped separately with their original durable receipt.
    aws::verify_backend(api, &request.administrator, &request.team)?;
    let mut access = request.access();
    if request.existing.is_some() {
        inspect_external(api, request)?;
    } else {
        let exists = stack.exists()?;
        ensure!(
            !exists || receipt.stack_started,
            "administrator stack exists without a local ownership receipt; recover its original receipt"
        );
        ensure!(
            exists || !receipt.complete,
            "completed administrator stack is missing; investigate instead of recreating IAM resources"
        );
        receipt.stack_started = true;
        receipt.uncertain = true;
        foundation::write_json(&receipt_path, &receipt)?;
        stack.prepare(!exists)?;
        if reconcile && exists {
            stack.refresh()?;
        }
        // Old completed receipts can only describe the current naming scheme.
        // An incomplete pre-fix receipt is resolved from the validated checkpoint.
        let pinned = receipt
            .selected_access
            .clone()
            .or_else(|| receipt.complete.then(|| request.access()));
        access = stack.configure(request, pinned.as_ref())?;
        access.validate(&request.team)?;
        ensure!(
            access.management == RoleManagement::Zdn
                && pinned.as_ref().is_none_or(|saved| *saved == access),
            "administrator recovery attempted to change saved deployment access"
        );
        receipt.selected_access = Some(access.clone());
        foundation::write_json(&receipt_path, &receipt)?;
        stack.apply()?;
        let output = stack.outputs()?;
        ensure!(
            output
                == json!({"roleArn":access.role_arn,"runtimeBoundaryArn":access.runtime_boundary_arn}),
            "administrator outputs differ from the requested role or boundary"
        );
    }
    receipt.complete = true;
    receipt.uncertain = false;
    foundation::write_json(&receipt_path, &receipt)?;
    request.completed_team_with_access(access)
}

/// Check the deployment source, not necessarily the administrator, before
/// provisioning backend authority. STS omits IAM role paths, so resolve the
/// source role and bind its immutable ID rather than synthesizing an ARN.
pub fn verify_source_identity(
    api: &dyn AwsApi,
    selection: &aws::AwsSelection,
    trusted_principals: &[String],
) -> Result<()> {
    let caller = aws::verify_identity(api, selection)?;
    let resource = caller.arn.splitn(6, ':').nth(5).unwrap();
    let principal = if let Some(role) = resource.strip_prefix("assumed-role/") {
        let (name, session) = role
            .split_once('/')
            .context("invalid assumed-role caller")?;
        ensure!(
            caller.arn.starts_with("arn:aws:sts::")
                && !name.is_empty()
                && !session.is_empty()
                && !session.contains('/'),
            "invalid assumed-role caller"
        );
        let role = api.call("iam", "get-role", json!({"RoleName":name}), &[])?;
        let arn = role["Role"]["Arn"]
            .as_str()
            .context("source role ARN missing")?;
        let role_id = role["Role"]["RoleId"]
            .as_str()
            .context("source role ID missing")?;
        access::iam_resource(arn, &selection.account_id, "role")?;
        ensure!(
            arn.rsplit('/').next() == Some(name)
                && role["Role"]["RoleName"] == name
                && !role_id.is_empty()
                && Some(role_id) == caller.user_id.strip_suffix(&format!(":{session}")),
            "source role identity mismatch"
        );
        arn.to_owned()
    } else {
        access::iam_resource(&caller.arn, &selection.account_id, "user")?;
        caller.arn
    };
    ensure!(
        trusted_principals.contains(&principal),
        "source caller does not match any selected trusted principal"
    );
    Ok(())
}

/// External roles are inspected, never imported into Pulumi or changed. Trust
/// conditions and effective permissions still require successful assumption and
/// the live qualification; a matching statement alone is not authorization.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "access_bootstrap.inspect_external")
)]
pub fn inspect_external(api: &dyn AwsApi, request: &AccessRequest) -> Result<()> {
    request.validate()?;
    let access = request
        .existing
        .as_ref()
        .context("no external role selected")?;
    let name = access.role_arn.rsplit('/').next().unwrap();
    let role = api.call("iam", "get-role", json!({"RoleName":name}), &[])?;
    ensure!(
        role.pointer("/Role/Arn").and_then(Value::as_str) == Some(&access.role_arn),
        "external role ARN differs from selected account/path"
    );
    let trust = role
        .pointer("/Role/AssumeRolePolicyDocument/Statement")
        .context("external role has no decoded trust policy")?;
    let statements = if let Some(statements) = trust.as_array() {
        statements.clone()
    } else {
        vec![trust.clone()]
    };
    let includes = |value: &Value, expected: &str| {
        value.as_str() == Some(expected)
            || value
                .as_array()
                .is_some_and(|items| items.iter().any(|v| v.as_str() == Some(expected)))
    };
    for principal in &request.trusted_principals {
        ensure!(
            statements.iter().any(|s| s["Effect"] == "Allow"
                && includes(&s["Action"], "sts:AssumeRole")
                && includes(&s["Principal"]["AWS"], principal)),
            "external trust does not explicitly include every selected principal"
        );
    }
    let boundary = api.call(
        "iam",
        "get-policy",
        json!({"PolicyArn":access.runtime_boundary_arn}),
        &[],
    )?;
    ensure!(
        boundary.pointer("/Policy/Arn").and_then(Value::as_str)
            == Some(&access.runtime_boundary_arn),
        "external runtime boundary is missing or has a different ARN"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "access_bootstrap.live_stack")
)]
pub fn live_stack(
    request: &AccessRequest,
    directory: &Path,
    managed: &Path,
    cancel: Arc<AtomicBool>,
) -> Result<AccessClient<SystemPulumiRunner>> {
    request.validate()?;
    foundation::private_directory(directory)?;
    let project = directory.join("project");
    foundation::private_directory(&project)?;
    // This provisional program supplies project/provider metadata for stack
    // selection and refresh. Configure resolves recovery names before the
    // actual Pulumi preview. It is not an approved recovery plan.
    let program = request.render()?;
    foundation::write_private(
        &project.join("Pulumi.yaml"),
        serde_yaml::to_string(&program)?.as_bytes(),
    )?;
    let client = PulumiClient::new(
        PulumiWorkspace {
            tools: ManagedTools::resolve(managed)?,
            work_dir: project,
            diagnostics_dir: directory.join("diagnostics"),
            backend_url: access::admin_backend(&request.team)?,
            secrets_provider: request.team.secrets_provider(),
            aws: AwsContext {
                profile: request.administrator.profile.clone(),
                account_id: request.team.aws.account_id.clone(),
                region: request.team.aws.region.clone(),
                credential_files: None,
            },
            project: "zdn-access".into(),
            stack: format!("zdn-{}", request.team.bootstrap_id.simple()),
        },
        SystemPulumiRunner::current_exe()?,
    )?;
    Ok(AccessClient { client, cancel })
}

/// External-role verification cannot accidentally invoke a Pulumi mutation.
pub struct NoStack;
impl AccessStack for NoStack {
    fn exists(&mut self) -> Result<bool> {
        eyre::bail!("external roles have no managed stack")
    }
    fn prepare(&mut self, _: bool) -> Result<()> {
        eyre::bail!("external roles have no managed stack")
    }
    fn refresh(&mut self) -> Result<()> {
        eyre::bail!("external roles have no managed stack")
    }
    fn configure(
        &mut self,
        _: &AccessRequest,
        _: Option<&DeploymentAccess>,
    ) -> Result<DeploymentAccess> {
        eyre::bail!("external roles have no managed stack")
    }
    fn apply(&mut self) -> Result<()> {
        eyre::bail!("external roles have no managed stack")
    }
    fn outputs(&mut self) -> Result<Value> {
        eyre::bail!("external roles have no managed stack")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn recovery_request() -> AccessRequest {
        serde_json::from_value(json!({
            "team":{"apiVersion":"zdn-team/v1alpha1","teamId":"recovery","revision":1,
                "bootstrapId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
                "aws":{"accountId":"123456789012","region":"us-east-1"},
                "state":{"backend":"s3://zdn-recovery/pulumi/zdn","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"}},
            "administrator":{"profile":"admin","accountId":"123456789012","region":"us-east-1"},
            "trustedPrincipals":["arn:aws:iam::123456789012:user/developer"],"existing":null
        })).unwrap()
    }

    fn original_boundary_document() -> Value {
        json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":[
            "ssm:UpdateInstanceInformation","ssmmessages:CreateControlChannel",
            "ssmmessages:CreateDataChannel","ssmmessages:OpenControlChannel",
            "ssmmessages:OpenDataChannel"],"Resource":"*"}]})
    }

    fn policy_checkpoint(logical: &str, suffix: &str, document: Value) -> Value {
        json!({
            "urn":format!("urn:pulumi:zdn-a81c4e9b46124e0da3fac4ab68a04153::zdn-access::aws:iam/policy:Policy::{logical}"),
            "type":"aws:iam/policy:Policy","protect":true,
            "id":format!("arn:aws:iam::123456789012:policy/zdn-admin/a81c4e9b-4612-4e0d-a3fa-c4ab68a04153/zdn-a81c4e9b46124e0da3fac4ab68a04153-{suffix}"),
            "inputs":{"name":format!("zdn-a81c4e9b46124e0da3fac4ab68a04153-{suffix}"),
                "path":"/zdn-admin/a81c4e9b-4612-4e0d-a3fa-c4ab68a04153/",
                "policy":document.to_string(),
                "tags":{"zdn:managed-by":"zdn","zdn:team-id":"recovery","zdn:bootstrap":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153"}}
        })
    }

    #[test]
    fn either_original_policy_winner_recovers_without_rename_or_boundary_repurpose() {
        let request = recovery_request();
        for boundary_won in [false, true] {
            let logical = if boundary_won {
                "runtimeBoundary"
            } else {
                "runtimePolicy"
            };
            let old = policy_checkpoint(logical, "runtime", original_boundary_document());
            let export = json!({"deployment":{"resources":[old]}});
            let selected = recovery_access(&request, None, &export).unwrap();
            let program = request.render_with_access(&selected).unwrap();
            let resources = &program["resources"];
            assert_eq!(
                resources[logical]["properties"]["name"],
                old["inputs"]["name"]
            );
            assert_eq!(
                resources[logical]["properties"]["path"],
                old["inputs"]["path"]
            );
            assert_eq!(resources[logical]["options"]["protect"], true);
            let boundary = &resources["runtimeBoundary"]["properties"];
            assert_eq!(
                serde_json::from_str::<Value>(boundary["policy"].as_str().unwrap()).unwrap(),
                access::runtime_boundary_for_team(&request.team).unwrap()
            );
            if boundary_won {
                assert_eq!(selected.runtime_boundary_arn, old["id"]);
                assert!(resources["runtimePolicy"]["properties"]["name"]
                    .as_str()
                    .unwrap()
                    .ends_with("-runtime-management"));
            } else {
                assert!(selected.runtime_boundary_arn.ends_with("-runtime-boundary"));
                assert_eq!(program, request.render().unwrap());
            }
            let names: std::collections::BTreeSet<_> = resources
                .as_object()
                .unwrap()
                .values()
                .filter(|v| v["type"] == "aws:iam:Policy")
                .map(|v| v["properties"]["name"].as_str().unwrap())
                .collect();
            assert_eq!(names.len(), 9);
            let completed = request
                .completed_team_with_access(selected.clone())
                .unwrap();
            let roundtrip: TeamDefinition =
                serde_yaml::from_str(&serde_yaml::to_string(&completed).unwrap()).unwrap();
            roundtrip.validate().unwrap();
            let repeated = AccessRequest {
                team: roundtrip,
                ..request.clone()
            };
            assert_eq!(repeated.render().unwrap(), program);
            assert_eq!(repeated.access(), selected);
            assert_eq!(
                recovery_access(&request, Some(&selected), &export).unwrap(),
                selected
            );
        }
    }

    #[test]
    fn recovery_keeps_current_and_pinned_names_when_resources_are_missing() {
        let request = recovery_request();
        let empty = json!({"deployment":{}});
        assert_eq!(
            recovery_access(&request, None, &empty).unwrap(),
            request.access()
        );
        let legacy = DeploymentAccess::legacy_managed(&request.team);
        assert_eq!(
            recovery_access(&request, Some(&legacy), &empty).unwrap(),
            legacy
        );
        let current = json!({"deployment":{"resources":[policy_checkpoint("runtimeBoundary", "runtime-boundary", original_boundary_document())]}});
        assert_eq!(
            recovery_access(&request, None, &current).unwrap(),
            request.access()
        );
        assert!(recovery_access(&request, Some(&legacy), &current).is_err());
    }

    #[test]
    fn recovery_rejects_ambiguous_foreign_modified_or_conflicting_policies() {
        let request = recovery_request();
        let boundary =
            policy_checkpoint("runtimeBoundary", "runtime", original_boundary_document());
        let valid = json!({"deployment":{"resources":[boundary]}});
        assert!(recovery_access(&request, Some(&request.access()), &valid).is_err());
        for (pointer, value) in [
            ("/id", json!("arn:aws:iam::999999999999:policy/foreign")),
            ("/inputs/name", json!("foreign")),
            ("/inputs/path", json!("/foreign/")),
            ("/inputs/tags/zdn:bootstrap", json!("foreign")),
            (
                "/inputs/policy",
                json!(
                    "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
                ),
            ),
            ("/protect", json!(false)),
            ("/type", json!("aws:iam/role:Role")),
            (
                "/urn",
                json!("urn:pulumi:foreign::zdn-access::aws:iam/policy:Policy::runtimeBoundary"),
            ),
        ] {
            let mut changed = valid.clone();
            *changed["deployment"]["resources"][0]
                .pointer_mut(pointer)
                .unwrap() = value;
            assert!(
                recovery_access(&request, None, &changed).is_err(),
                "{pointer}"
            );
        }
        for (key, value) in [("delete", json!(true)), ("external", json!(true))] {
            let mut changed = valid.clone();
            changed["deployment"]["resources"][0][key] = value;
            assert!(recovery_access(&request, None, &changed).is_err(), "{key}");
        }
        for extra in [
            boundary,
            policy_checkpoint("runtimePolicy", "runtime", json!({})),
        ] {
            let mut changed = valid.clone();
            changed["deployment"]["resources"]
                .as_array_mut()
                .unwrap()
                .push(extra);
            assert!(recovery_access(&request, None, &changed).is_err());
        }
        let mut pending = valid;
        pending["deployment"]["pending_operations"] = json!([{"type":"creating","resource":{}}]);
        assert!(recovery_access(&request, None, &pending).is_err());
    }

    #[derive(Default)]
    struct FakeRuntime {
        now: Cell<Duration>,
        waits: RefCell<Vec<Duration>>,
        cancel: AtomicBool,
        cancel_at: Cell<Option<Duration>>,
    }

    impl Runtime for FakeRuntime {
        fn unix_time(&self) -> Result<u64> {
            Ok(0)
        }
        fn monotonic(&self) -> Duration {
            self.now.get()
        }
        fn sleep(&self, duration: Duration) {
            self.waits.borrow_mut().push(duration);
            self.now.set(self.now.get() + duration);
            if self.cancel_at.get().is_some_and(|at| self.now.get() >= at) {
                self.cancel.store(true, Ordering::SeqCst);
            }
        }
    }

    fn api_error(code: &str) -> eyre::Report {
        aws::AwsApiError { code: code.into() }.into()
    }

    #[test]
    fn developer_verification_retries_only_typed_iam_denials_until_success() {
        for code in ["403", "AccessDenied", "AccessDeniedException"] {
            let runtime = FakeRuntime::default();
            let mut attempts = Vec::new();
            wait_for_permissions(
                || {
                    attempts.push(runtime.monotonic());
                    if attempts.len() < 3 {
                        Err(api_error(code).wrap_err("backend check"))
                    } else {
                        Ok(())
                    }
                },
                &runtime,
                &runtime.cancel,
            )
            .unwrap();
            assert_eq!(
                attempts,
                [0, 1, 3].map(Duration::from_secs),
                "retry times for {code}"
            );
            assert!(runtime
                .waits
                .borrow()
                .iter()
                .all(|wait| *wait <= Duration::from_millis(500)));
        }
    }

    #[test]
    fn developer_verification_stops_at_the_monotonic_retry_deadline() {
        let runtime = FakeRuntime::default();
        let mut attempts = Vec::new();
        let error = wait_for_permissions(
            || {
                attempts.push(runtime.monotonic());
                Err(api_error("AccessDenied"))
            },
            &runtime,
            &runtime.cancel,
        )
        .unwrap_err();
        assert_eq!(attempts, [0, 1, 3, 7, 15, 30, 45].map(Duration::from_secs));
        assert_eq!(runtime.monotonic(), Duration::from_secs(60));
        assert!(error.to_string().contains("60-second retry window"));
        assert_eq!(
            error.downcast_ref::<aws::AwsApiError>().unwrap().code,
            "AccessDenied"
        );
    }

    #[test]
    fn developer_verification_counts_api_time_against_the_retry_window() {
        let runtime = FakeRuntime::default();
        let mut attempts = 0;
        let error = wait_for_permissions(
            || {
                attempts += 1;
                runtime
                    .now
                    .set(runtime.monotonic() + Duration::from_secs(40));
                Err(api_error("403"))
            },
            &runtime,
            &runtime.cancel,
        )
        .unwrap_err();
        assert_eq!(attempts, 2);
        assert_eq!(runtime.monotonic(), Duration::from_secs(81));
        assert_eq!(
            runtime.waits.borrow().iter().sum::<Duration>(),
            Duration::from_secs(1)
        );
        assert!(error.to_string().contains("60-second retry window"));
    }

    #[test]
    fn developer_verification_returns_permanent_errors_without_waiting() {
        let errors = [
            api_error("ExpiredToken"),
            api_error("ExpiredTokenException"),
            api_error("InvalidClientTokenId"),
            api_error("CommandFailed"),
            api_error("CommandInterrupted"),
            eyre::eyre!("selected account/region conflicts with team definition"),
            eyre::eyre!("AWS credentials do not match the selected deployment role"),
            eyre::eyre!("state bucket must use the team's KMS encryption key"),
            eyre::eyre!("AWS request failed (403)"),
        ];
        for error in errors {
            let message = error.to_string();
            let mut error = Some(error);
            let runtime = FakeRuntime::default();
            let mut attempts = 0;
            let result = wait_for_permissions(
                || {
                    attempts += 1;
                    Err(error.take().expect("permanent error must not repeat"))
                },
                &runtime,
                &runtime.cancel,
            );
            assert_eq!(result.unwrap_err().to_string(), message);
            assert_eq!(attempts, 1);
            assert!(runtime.waits.borrow().is_empty());
        }
    }

    #[test]
    fn developer_verification_cancellation_prevents_calls_and_interrupts_waits() {
        for cancel_before_call in [true, false] {
            let runtime = FakeRuntime::default();
            runtime.cancel.store(cancel_before_call, Ordering::SeqCst);
            runtime.cancel_at.set(Some(Duration::from_millis(250)));
            let mut attempts = 0;
            let error = wait_for_permissions(
                || {
                    attempts += 1;
                    Err(api_error("403"))
                },
                &runtime,
                &runtime.cancel,
            )
            .unwrap_err();
            assert!(error.to_string().contains("cancelled"));
            assert_eq!(attempts, usize::from(!cancel_before_call));
            assert!(runtime.monotonic() <= Duration::from_millis(500));
        }
    }

    #[test]
    fn developer_verification_does_not_publish_success_after_cancellation() {
        let runtime = FakeRuntime::default();
        let error = wait_for_permissions(
            || {
                runtime.cancel.store(true, Ordering::SeqCst);
                Ok(())
            },
            &runtime,
            &runtime.cancel,
        )
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert!(runtime.waits.borrow().is_empty());
    }

    #[test]
    fn access_lock_releases_even_if_another_descriptor_is_open() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lock");
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.try_lock_exclusive().unwrap();
        let inherited = file.try_clone().unwrap();
        drop(AccessLock(file));
        let next = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        next.try_lock_exclusive().unwrap();
        FileExt::unlock(&next).unwrap();
        drop(inherited);
    }
}
