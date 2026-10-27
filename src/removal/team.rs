use super::*;
use crate::{
    access::RoleManagement,
    aws::{self, AwsSelection, BootstrapReceipt, LocalProfile, TeamDefinition},
    build_infra::BuildInfrastructure,
    foundation::DeploymentFile,
};
use std::path::PathBuf;
use uuid::Uuid;

const PARTICIPANT_CLOSURE_SCOPE: &str = "exact participant targets terminated or absent, granted documents absent, active sessions absent; resource closure only, not STS invalidation or StartSession/GetDocument denial";
const MAX_S3_VERSION_PAGES: usize = 100;
const MAX_S3_VERSIONS: usize = 10_000;

pub struct TeamRemovalOptions {
    pub delete_data: bool,
    pub writers_stopped: bool,
    pub reconcile: bool,
    /// Useful bounded intermediate: remove managed access/build infrastructure,
    /// but preserve the backend and enabled KMS key for independent inspection.
    pub keep_backend: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TeamReceipt {
    version: u32,
    creation: Value,
    local_evidence: Value,
    uncertain: bool,
    access_removed: bool,
    backend_started: bool,
    backend_removed: bool,
    build_data: Option<Value>,
    backend_plan: Option<Vec<Value>>,
    kms_deletion_date: Option<Value>,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.creation")
)]
fn creation(profile: &Path) -> Result<(LocalProfile, BootstrapReceipt, Option<AccessReceipt>)> {
    let local: LocalProfile = foundation::read_json(profile)?;
    local.validate()?;
    let original: BootstrapReceipt = foundation::read_json(&profile.with_extension("bootstrap.json"))
        .context("team deletion requires the original local bootstrap creation receipt; importing a profile is not ownership")?;
    let team = &local.team;
    ensure!(
        original.version == 1
            && original.complete
            && original.bucket_created
            && original.bucket_creation_started
            && original.key_creation_started
            && original.bootstrap_id == team.bootstrap_id
            && original.request.team_id == team.team_id
            && original.request.account_id == team.aws.account_id
            && original.request.region == team.aws.region
            && original.request.bucket == team.backend_bucket()?
            && original.request.prefix == team.backend_prefix()?
            && original.key_arn.as_deref() == Some(team.state.kms_key_arn.as_str()),
        "bootstrap receipt does not authorize this backend; finish/recover original setup first"
    );
    let access_path = profile.with_extension("access").join("access.json");
    let access: Option<AccessReceipt> = if access_path.try_exists()? {
        let saved: AccessReceipt = foundation::read_json(&access_path)?;
        saved.request.validate()?;
        ensure!(
            saved.version == 1 && saved.complete && !saved.uncertain,
            "administrator setup is incomplete or uncertain; finish setup before team removal"
        );
        let selected = saved
            .selected_access
            .clone()
            .unwrap_or_else(|| saved.request.access());
        ensure!(
            saved.request.completed_team_with_access(selected)? == *team,
            "administrator creation receipt differs from selected local team"
        );
        Some(saved)
    } else {
        ensure!(
            team.deployment.is_none(),
            "missing original administrator creation receipt"
        );
        None
    };
    Ok((local, original, access))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.team_plan")
)]
pub fn team_plan(profile: &Path) -> Result<Value> {
    let (local, original, access) = creation(profile)?;
    let managed = access
        .as_ref()
        .is_some_and(|r| r.request.existing.is_none());
    Ok(
        json!({"kind":"team-removal","team":local.team,"bootstrapReceipt":original,
        "cloudChanges":false,"liveOwnershipChecked":false,"managedAdministratorStack":managed,
        "externalRolesPreserved":true,
        "participantClosureScope":PARTICIPANT_CLOSURE_SCOPE,
        "actions":["require destroyed networks with no retained data and independently empty live inventory",
        "require separate participant removal and fresh exact target/document/session resource closure (not cached-token denial)", "refuse active/unreceipted builds and unknown objects",
        "delete exact receipted build data/images with --delete-data", "unprotect and destroy owned access/build stack",
        "inspect exact empty current checkpoints, purge owned versioned backend data, delete backend last", "schedule KMS deletion for 30 days; report pending date"],
        "requiredConsent":["--yes","--delete-data","--writers-stopped"],
        "limits":"Proposal from local receipts only. Live execution rechecks all ownership. No automatic repair, refresh, arbitrary prefix purge, active-session termination or network destruction. --keep-backend stops after access/build removal."}),
    )
}

/// Full team cleanup is deliberately downstream of product network/data and
/// participant cleanup. The caller holds the profile lock; this also takes the
/// exact bootstrap/access locks used by their creation lifecycles.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.remove_team")
)]
pub fn remove_team(
    api: &dyn AwsApi,
    selection: &AwsSelection,
    state: &Path,
    profile: &Path,
    mut stack: Option<&mut dyn RemovalStack>,
    options: &TeamRemovalOptions,
) -> Result<Value> {
    ensure!(
        options.delete_data && options.writers_stopped,
        "team removal requires --delete-data and --writers-stopped; stop all other controllers/build writers first"
    );
    let bootstrap_path = profile.with_extension("bootstrap.json");
    let path = bootstrap_path.with_extension("removal.json");
    let _bootstrap_lock = lock(&bootstrap_path.with_extension("lock"))?;
    let (local, bootstrap, access) = creation(profile)?;
    let team = &local.team;
    ensure!(
        selection.account_id == team.aws.account_id && selection.region == team.aws.region,
        "administrator selection differs from team"
    );
    if let Some(access) = &access {
        ensure!(
            access.request.administrator == *selection,
            "use the original administrator AWS profile"
        );
    }
    aws::verify_identity(api, selection)?;
    let evidence = local_evidence(api, state, team, options.reconcile)?;
    let original = json!({"profile":local,"bootstrap":bootstrap,"access":access});
    let mut receipt = if path.try_exists()? {
        let saved: TeamReceipt = foundation::read_json(&path)?;
        ensure!(
            saved.version == 1
                && saved.creation == original
                && cleanup_identity_evidence(&saved.local_evidence)
                    == cleanup_identity_evidence(&evidence),
            "team creation or local cleanup evidence changed since removal began"
        );
        ensure!(
            !saved.uncertain || options.reconcile,
            "team removal outcome uncertain; inspect and use --reconcile"
        );
        saved
    } else {
        aws::verify_backend_for_cleanup(api, selection, team)?;
        // Complete read-only preflight before the first removal receipt/effect.
        check_key(api, team, false)?;
        TeamReceipt {
            version: 1,
            creation: original,
            local_evidence: evidence.clone(),
            uncertain: false,
            access_removed: false,
            backend_started: false,
            backend_removed: false,
            build_data: None,
            backend_plan: None,
            kms_deletion_date: None,
        }
    };
    if !receipt.backend_started {
        aws::verify_backend_for_cleanup(api, selection, team)?;
    }
    let backend_absent = if receipt.backend_started {
        match api.call(
            "s3api",
            "head-bucket",
            bucket_input(team, team.backend_bucket()?),
            &[],
        ) {
            Ok(_) => false,
            Err(e) if missing(&e, &["NoSuchBucket", "404", "NotFound"]) => true,
            Err(e) => return Err(e),
        }
    } else {
        false
    };
    // Resumes must recheck every key consumer before any further effect, even
    // when stopping at the keep-backend boundary. PendingDeletion is only
    // recoverable once the receipted backend deletion is independently observed.
    check_key(api, team, backend_absent)?;
    no_infrastructure(
        api,
        team,
        access.as_ref().filter(|_| !receipt.access_removed),
    )?;
    if let Some(access) = &access {
        if access.request.existing.is_none() {
            let directory = profile.with_extension("access");
            let _access_lock = lock(&directory.join("access.lock"))?;
            let access_path = directory.join("removal.json");
            if receipt.access_removed {
                let saved: StackRemovalReceipt = foundation::read_json(&access_path)?;
                ensure!(
                    saved.version == 1
                        && saved.creation == serde_json::to_value(access)?
                        && saved.stack_removed
                        && !saved.uncertain,
                    "administrator removal evidence changed"
                );
                validate_access_checkpoint(access, &saved.checkpoint)?;
                verify_access_absent(api, &saved.checkpoint)?;
            } else {
                let stack = stack
                    .as_mut()
                    .context("managed administrator removal requires Pulumi tools")?;
                let current = stack.checkpoint()?;
                // Validate everything before saving intent, including build/job/data
                // ownership. No forceDestroy/forceDelete program overrides are used.
                if !access_path.try_exists()? {
                    validate_access_checkpoint(
                        access,
                        current
                            .as_ref()
                            .context("administrator stack missing without removal evidence")?,
                    )?;
                    validate_live_access(api, access, current.as_ref().unwrap(), false)?;
                }
                let build = BuildInfrastructure::for_team(team)?;
                check_builds(api, &build, &evidence)?;
                let mut deleted_configuration = (false, false);
                if access_path.try_exists()? {
                    let saved: StackRemovalReceipt = foundation::read_json(&access_path)?;
                    ensure!(
                        saved.version == 1 && saved.creation == serde_json::to_value(access)?,
                        "administrator removal evidence changed"
                    );
                    ensure!(
                        !saved.uncertain || options.reconcile,
                        "removal outcome uncertain; inspect and use --reconcile"
                    );
                    validate_access_checkpoint(access, &saved.checkpoint)?;
                    if let Some(current) = &current {
                        ensure!(!saved.stack_removed, "removed stack reappeared");
                        validate_remaining(&saved.checkpoint, current)?;
                    }
                    // Only a saved, authorized destroy and a validated remaining
                    // checkpoint explain provider deletion of these resources.
                    if receipt.build_data.is_some() {
                        let remaining = current.as_ref().map(resources).transpose()?.unwrap_or(&[]);
                        deleted_configuration = (
                            !remaining.iter().any(|r| {
                                r["urn"]
                                    .as_str()
                                    .is_some_and(|u| u.ends_with("::buildBucketPolicy"))
                            }),
                            !remaining.iter().any(|r| {
                                r["urn"]
                                    .as_str()
                                    .is_some_and(|u| u.ends_with("::buildBucketVersioning"))
                            }),
                        );
                    }
                }
                let data = build_data(api, team, &build, &evidence, deleted_configuration)?;
                if let Some(saved) = &receipt.build_data {
                    ensure_subset(array(saved, "objects")?, array(&data, "objects")?)?;
                    ensure!(
                        array(&data, "images")?
                            .iter()
                            .all(|v| array(saved, "images").is_ok_and(|items| items.contains(v))),
                        "ECR images changed during removal"
                    );
                    for (key, value) in data["identity"]
                        .as_object()
                        .context("build identity missing")?
                    {
                        ensure!(
                            saved["identity"][key] == *value,
                            "build resource incarnation changed during removal"
                        );
                    }
                } else if !access_path.try_exists()? {
                    ensure!(
                        data["identity"].as_object().is_some_and(|v| v.len() == 3),
                        "completed build infrastructure is missing; investigate before removal"
                    );
                }
                // Reject foreign backend namespaces/active network checkpoints even
                // when stopping at the intermediate access-removal boundary.
                backend_data(api, team, &evidence, true)?;
                let mut access_receipt = open_stack_receipt(
                    &access_path,
                    &serde_json::to_value(access)?,
                    current.as_ref(),
                    options.reconcile,
                    |checkpoint| validate_access_checkpoint(access, checkpoint),
                )?;
                validate_live_access(api, access, &access_receipt.checkpoint, true)?;
                if receipt.build_data.is_none() {
                    receipt.build_data = Some(data.clone());
                }
                receipt.uncertain = true;
                foundation::write_json(&path, &receipt)?;
                purge_build_data(api, team, &build, &data)?;
                teardown_stack(
                    &access_path,
                    &mut access_receipt,
                    current.as_ref(),
                    *stack,
                    |checkpoint| verify_access_absent(api, checkpoint),
                )?;
                verify_access_absent(api, &access_receipt.checkpoint)?;
                access_receipt.uncertain = false;
                foundation::write_json(&access_path, &access_receipt)?;
            }
        } else {
            ensure!(
                team.deployment
                    .as_ref()
                    .is_some_and(|a| a.management == RoleManagement::External),
                "external access receipt mismatch"
            );
        }
    }
    receipt.access_removed = true;
    receipt.uncertain = false;
    foundation::write_json(&path, &receipt)?;
    no_infrastructure(api, team, None)?;
    if options.keep_backend {
        return Ok(
            json!({"status":"access-removed-backend-preserved","teamId":team.team_id,
            "participantClosureScope":PARTICIPANT_CLOSURE_SCOPE,
            "externalRolesPreserved":true,"backendRemoved":false,"kmsDeleted":false,"receipt":path}),
        );
    }
    // IAM and builds are gone before state is purged. No live checkpoint with
    // resources (including a .json.bak) is ever implicitly allowed.
    if !receipt.backend_removed {
        match api.call(
            "s3api",
            "head-bucket",
            bucket_input(team, team.backend_bucket()?),
            &[],
        ) {
            Err(error)
                if receipt.backend_started
                    && missing(&error, &["NoSuchBucket", "404", "NotFound"]) => {}
            Err(error) => return Err(error),
            Ok(_) => {
                aws::verify_backend_for_cleanup(api, selection, team)?;
                let objects = backend_data(api, team, &evidence, false)?;
                if let Some(saved) = &receipt.backend_plan {
                    ensure_subset(saved, &objects)?;
                } else {
                    receipt.backend_plan = Some(objects.clone());
                }
                receipt.backend_started = true;
                receipt.uncertain = true;
                foundation::write_json(&path, &receipt)?;
                purge_versions(api, team, team.backend_bucket()?, &objects)?;
                ensure!(
                    versions(api, team, team.backend_bucket()?)?.is_empty(),
                    "backend changed during removal; stop writers and reconcile"
                );
                api.call(
                    "s3api",
                    "delete-bucket",
                    bucket_input(team, team.backend_bucket()?),
                    &[],
                )?;
            }
        }
        require_absent(
            api,
            "s3api",
            "head-bucket",
            bucket_input(team, team.backend_bucket()?),
            &["NoSuchBucket", "404", "NotFound"],
        )?;
        receipt.backend_removed = true;
        foundation::write_json(&path, &receipt)?;
    } else {
        require_absent(
            api,
            "s3api",
            "head-bucket",
            bucket_input(team, team.backend_bucket()?),
            &["NoSuchBucket", "404", "NotFound"],
        )?;
    }
    let metadata = check_key(api, team, true)?;
    if metadata["KeyState"] != "PendingDeletion" {
        receipt.uncertain = true;
        foundation::write_json(&path, &receipt)?;
        api.call(
            "kms",
            "schedule-key-deletion",
            json!({"KeyId":team.state.kms_key_arn,"PendingWindowInDays":30}),
            &[],
        )?;
    }
    let metadata = check_key(api, team, true)?;
    ensure!(
        metadata["KeyState"] == "PendingDeletion" && !metadata["DeletionDate"].is_null(),
        "KMS deletion scheduling is not observed"
    );
    receipt.kms_deletion_date = Some(metadata["DeletionDate"].clone());
    receipt.uncertain = false;
    foundation::write_json(&path, &receipt)?;
    Ok(
        json!({"status":"kms-deletion-pending","teamId":team.team_id,"accessRemoved":true,"backendRemoved":true,
        "participantClosureScope":PARTICIPANT_CLOSURE_SCOPE,
        "externalRolesPreserved":true,"kmsDeleted":false,"kmsState":"PendingDeletion","kmsDeletionDate":receipt.kms_deletion_date,"receipt":path}),
    )
}

/// Compare original ownership and cleanup verdicts, not unrelated bookkeeping.
/// Keep the saved evidence untouched, including receipts written by older zdn.
/// Fresh local_evidence still revalidates every verdict and live absence check.
fn cleanup_identity_evidence(evidence: &Value) -> Value {
    let mut identity = evidence.clone();
    if let Some(networks) = identity["networks"].as_object_mut() {
        for deployment in networks.values_mut() {
            if let Some(deployment) = deployment.as_object_mut() {
                deployment.remove("last_operation");
            }
        }
    }
    if let Some(participants) = identity["participants"].as_object_mut() {
        for removal in participants.values_mut() {
            if let Some(removal) = removal.as_object_mut() {
                removal.remove("revocationVerified");
            }
        }
    }
    identity
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.local_evidence")
)]
fn local_evidence(
    api: &dyn AwsApi,
    state: &Path,
    team: &TeamDefinition,
    reconcile: bool,
) -> Result<Value> {
    let mut networks = BTreeMap::new();
    let mut builds = Vec::new();
    for directory in directories(&state.join("foundation"))? {
        let id = Uuid::parse_str(
            directory
                .file_name()
                .and_then(|s| s.to_str())
                .context("invalid network directory")?,
        )?;
        let deployment = DeploymentFile::read_snapshot(state, id)?;
        if deployment.team.bootstrap_id != team.bootstrap_id {
            continue;
        }
        ensure!(
            deployment.team == *team
                && deployment.destroyed
                && deployment.unresolved_operation.is_none(),
            "active network or changed network ownership; destroy network first"
        );
        deployment
            .cleanup
            .as_ref()
            .context("network cleanup evidence missing")?
            .validate(true)?;
        let observed = crate::foundation_live::inventory(api, &deployment)?;
        ensure!(
            observed.remaining_resources.is_empty() && observed.retained_volumes.is_empty(),
            "network infrastructure or retained data still exists"
        );
        for service in [
            crate::endpoints::Service::NodeRpc,
            crate::endpoints::Service::LightwalletGrpc,
        ] {
            require_absent(
                api,
                "ssm",
                "describe-document",
                json!({"Name":service.document_name(team.bootstrap_id, id)}),
                &["InvalidDocument"],
            )?;
        }
        if let Some(outputs) = &deployment.outputs {
            let mut instances = BTreeSet::from([outputs.instance_id.clone()]);
            instances.extend(outputs.nodes.values().map(|n| n.instance_id.clone()));
            for instance in instances {
                let sessions = api.call(
                    "ssm",
                    "describe-sessions",
                    json!({"State":"Active","Filters":[{"key":"Target","value":instance}]}),
                    &[],
                )?;
                ensure!(
                    array(&sessions, "Sessions")?.is_empty() && no_token(&sessions),
                    "active network sessions remain"
                );
            }
        }
        if directory.join("build/attempt.json").try_exists()? {
            if reconcile {
                crate::build_job::reconcile_for_removal(api, &directory.join("build"), team)?;
            }
            builds.push(crate::build_job::removal_evidence(
                &directory.join("build"),
                team,
            )?);
        }
        for update in directories(&directory.join("updates"))? {
            if update.join("build/attempt.json").try_exists()? {
                if reconcile {
                    crate::build_job::reconcile_for_removal(api, &update.join("build"), team)?;
                }
                builds.push(crate::build_job::removal_evidence(
                    &update.join("build"),
                    team,
                )?);
            }
        }
        networks.insert(id.to_string(), serde_json::to_value(&deployment)?);
    }
    let participants = state
        .join("participants")
        .join(team.bootstrap_id.to_string());
    let mut grants = BTreeMap::new();
    for directory in directories(&participants)? {
        let creation_path = directory.join("participant.json");
        match fs::symlink_metadata(&creation_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Project preparation and failed read-only preflight may leave
                // directories, but every stack effect requires a saved receipt.
                ensure!(
                    fs::symlink_metadata(directory.join("removal.json"))
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
                    "participant removal is missing its original creation receipt"
                );
                continue;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let creation: ParticipantReceipt = foundation::read_json(&creation_path)?;
        creation.request.validate()?;
        ensure!(
            creation.version == 1
                && (creation.stack_started || (!creation.uncertain && !creation.complete))
                && creation.request.team == *team,
            "participant receipt differs from team"
        );
        let removal: StackRemovalReceipt =
            foundation::read_json(&directory.join("removal.json"))
                .context("remove separate participant grants before removing the team")?;
        ensure!(
            removal.version == 1
                && removal.creation == serde_json::to_value(&creation)?
                && removal.stack_removed
                && !removal.uncertain,
            "participant removal remains pending or uncertain"
        );
        if creation.stack_started {
            participant::validate_checkpoint(&creation.request, &removal.checkpoint)?;
        } else {
            ensure!(
                removal.checkpoint.is_null() && !removal.revocation_verified,
                "unstarted participant has no checkpoint ownership or revocation evidence"
            );
        }
        require_absent(
            api,
            "iam",
            "get-role",
            json!({"RoleName":creation.request.endpoints.participant_role_name()}),
            &["NoSuchEntity", "NoSuchEntityException"],
        )?;
        participant_resource_closure(api, &creation.request.endpoints)?;
        grants.insert(
            creation.request.endpoints.network_id.to_string(),
            serde_json::to_value(removal)?,
        );
    }
    Ok(json!({"networks":networks,"builds":builds,"participants":grants}))
}

/// Exact receipt identities, not tag inventory or possibly missing network outputs.
/// Observations are deliberately not serialized: terminated -> NotFound must not
/// change the equality-bound local evidence on a later reconciliation.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.participant_resource_closure")
)]
fn participant_resource_closure(
    api: &dyn AwsApi,
    endpoints: &crate::endpoints::EndpointFile,
) -> Result<()> {
    let targets: BTreeSet<_> = endpoints.targets.iter().map(|t| &t.instance_id).collect();
    for target in targets {
        match api.call(
            "ec2",
            "describe-instances",
            json!({"InstanceIds":[target]}),
            &[],
        ) {
            Err(e) if missing(&e, &["InvalidInstanceID.NotFound"]) => {}
            Err(e) => return Err(e),
            Ok(value) => {
                ensure!(
                    no_token(&value),
                    "incomplete participant instance inspection"
                );
                let reservations = array(&value, "Reservations")?;
                ensure!(
                    reservations.len() == 1,
                    "exact participant instance missing or ambiguous"
                );
                ensure!(
                    no_token(&reservations[0]),
                    "incomplete participant reservation"
                );
                let instances = array(&reservations[0], "Instances")?;
                ensure!(
                    instances.len() == 1
                        && instances[0]["InstanceId"].as_str() == Some(target.as_str())
                        && instances[0]["State"]["Name"] == "terminated"
                        && instances[0]["State"]["Code"] == 48,
                    "exact participant instance is live, malformed or mismatched"
                );
            }
        }
    }
    let services: BTreeSet<_> = endpoints.targets.iter().map(|t| t.service).collect();
    for service in services {
        require_absent(
            api,
            "ssm",
            "describe-document",
            json!({"Name":service.document_name(endpoints.bootstrap_id, endpoints.network_id)}),
            &["InvalidDocument"],
        )?;
    }
    no_sessions(api, endpoints)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.directories")
)]
fn directories(path: &Path) -> Result<Vec<PathBuf>> {
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    ensure!(
        fs::symlink_metadata(path)?.is_dir(),
        "receipt hierarchy must be real directories"
    );
    let mut result = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_dir(),
            "unknown file or symlink in receipt hierarchy"
        );
        result.push(entry.path());
    }
    result.sort();
    Ok(result)
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    Ok(value[key]
        .as_array()
        .with_context(|| format!("incomplete {key} inventory"))?
        .as_slice())
}
fn no_token(value: &Value) -> bool {
    ["NextToken", "nextToken", "Marker", "NextMarker"]
        .iter()
        .all(|k| value.get(k).is_none_or(|v| v == ""))
        && value.get("IsTruncated").is_none_or(|v| v == false)
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.tag_map")
)]
fn tag_map(value: &Value, key: &str, val: &str) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for tag in value.as_array().context("ownership tags missing")? {
        ensure!(
            result
                .insert(
                    tag[key].as_str().context("tag key missing")?.into(),
                    tag[val].clone()
                )
                .is_none(),
            "duplicate ownership tag"
        );
    }
    Ok(Value::Object(result))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.no_infrastructure")
)]
fn no_infrastructure(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    access: Option<&AccessReceipt>,
) -> Result<()> {
    let filters = json!([{"Name":"tag:zdn:bootstrap","Values":[team.bootstrap_id.to_string()]}]);
    let inventory = [
        ("describe-instances", "Reservations"),
        ("describe-volumes", "Volumes"),
        ("describe-snapshots", "Snapshots"),
        ("describe-vpcs", "Vpcs"),
        ("describe-subnets", "Subnets"),
        ("describe-security-groups", "SecurityGroups"),
        ("describe-route-tables", "RouteTables"),
        ("describe-network-interfaces", "NetworkInterfaces"),
        ("describe-internet-gateways", "InternetGateways"),
        ("describe-addresses", "Addresses"),
        ("describe-nat-gateways", "NatGateways"),
        ("describe-vpc-endpoints", "VpcEndpoints"),
    ];
    let calls: Vec<_> = inventory
        .iter()
        .map(|&(operation, field)| {
            let mut input = if field == "NatGateways" {
                json!({"Filter":filters})
            } else {
                json!({"Filters":filters})
            };
            if field == "Snapshots" {
                input["OwnerIds"] = json!([team.aws.account_id]);
            }
            crate::aws::AwsCall {
                operation,
                input,
                extra_args: Vec::new(),
            }
        })
        .collect();
    let values = api.batch_call("ec2", &calls)?;
    ensure!(
        values.len() == inventory.len(),
        "incomplete live infrastructure inventory"
    );
    for ((operation, field), value) in inventory.into_iter().zip(values) {
        let value = value?;
        ensure!(no_token(&value), "incomplete live infrastructure inventory");
        for resource in array(&value, field)? {
            let gone = if field == "Reservations" {
                array(resource, "Instances")?
                    .iter()
                    .all(|i| i["State"]["Name"] == "terminated")
            } else {
                field == "NatGateways" && resource["State"] == "deleted"
            };
            ensure!(gone, "active/unknown infrastructure remains: {operation}");
        }
    }
    // Path scans catch grants/runtime roles absent from local receipts. They are
    // refusals, never authority to delete an unrecorded IAM resource.
    let mut allowed_roles = BTreeSet::new();
    let mut allowed_policies = BTreeSet::new();
    if let Some(access) = access.filter(|r| r.request.existing.is_none()) {
        let selected = access
            .selected_access
            .as_ref()
            .context("selected access missing")?;
        let program = access.request.render_with_access(selected)?;
        for resource in program["resources"]
            .as_object()
            .context("access resources missing")?
            .values()
        {
            match resource["type"].as_str() {
                Some("aws:iam:Role") => {
                    allowed_roles.insert(
                        resource["properties"]["name"]
                            .as_str()
                            .context("role name missing")?
                            .to_owned(),
                    );
                }
                Some("aws:iam:Policy") => {
                    allowed_policies.insert(
                        resource["properties"]["name"]
                            .as_str()
                            .context("policy name missing")?
                            .to_owned(),
                    );
                }
                _ => {}
            }
        }
    }
    for path in [
        access::runtime_path(team),
        format!("/zdn-participants/{}/", team.bootstrap_id),
        access::admin_path(team),
    ] {
        let roles = api.call("iam", "list-roles", json!({"PathPrefix":path}), &[])?;
        ensure!(no_token(&roles), "incomplete IAM role inventory");
        for role in array(&roles, "Roles")? {
            ensure!(
                role["Path"] == access::admin_path(team)
                    && role["RoleName"]
                        .as_str()
                        .is_some_and(|n| allowed_roles.contains(n)),
                "unremoved or unknown team IAM role"
            );
        }
        let profiles = api.call(
            "iam",
            "list-instance-profiles",
            json!({"PathPrefix":path}),
            &[],
        )?;
        ensure!(
            no_token(&profiles) && array(&profiles, "InstanceProfiles")?.is_empty(),
            "team instance profiles remain"
        );
        let policies = api.call(
            "iam",
            "list-policies",
            json!({"Scope":"Local","PathPrefix":path}),
            &[],
        )?;
        ensure!(no_token(&policies), "incomplete IAM policy inventory");
        for policy in array(&policies, "Policies")? {
            ensure!(
                policy["Path"] == access::admin_path(team)
                    && policy["PolicyName"]
                        .as_str()
                        .is_some_and(|n| allowed_policies.contains(n)),
                "unremoved or unknown team IAM policy"
            );
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.validate_live_access")
)]
fn validate_live_access(
    api: &dyn AwsApi,
    creation: &AccessReceipt,
    checkpoint: &Value,
    allow_missing: bool,
) -> Result<()> {
    let list = aws_resources(checkpoint)?;
    for resource in &list {
        let kind = resource["type"].as_str().context("resource type missing")?;
        let id = resource["id"].as_str().context("resource ID missing")?;
        match kind {
            "aws:iam/role:Role" => {
                immutable_role(api, resource, allow_missing)?;
                let role = match api.call("iam", "get-role", json!({"RoleName":id}), &[]) {
                    Err(e)
                        if allow_missing
                            && missing(&e, &["NoSuchEntity", "NoSuchEntityException"]) =>
                    {
                        continue;
                    }
                    other => other?,
                };
                ensure!(
                    tag_map(&role["Role"]["Tags"], "Key", "Value")?
                        == access::admin_tags(&creation.request.team)
                        && participant::canonical_policy(
                            &role["Role"]["AssumeRolePolicyDocument"]
                        )? == participant::canonical_policy(&serde_json::from_str::<Value>(
                            resource["inputs"]["assumeRolePolicy"]
                                .as_str()
                                .context("role trust missing")?
                        )?)?
                        && role["Role"].get("PermissionsBoundary").is_none(),
                    "live administrator role drift"
                );
                let attached = api.call(
                    "iam",
                    "list-attached-role-policies",
                    json!({"RoleName":id}),
                    &[],
                )?;
                let expected: BTreeSet<_> = list
                    .iter()
                    .filter(|r| {
                        r["type"] == "aws:iam/rolePolicyAttachment:RolePolicyAttachment"
                            && r["inputs"]["role"] == id
                    })
                    .map(|r| r["inputs"]["policyArn"].as_str().unwrap_or_default())
                    .collect();
                ensure!(no_token(&attached), "incomplete attached policy inventory");
                for policy in array(&attached, "AttachedPolicies")? {
                    ensure!(
                        policy["PolicyArn"]
                            .as_str()
                            .is_some_and(|a| expected.contains(a)),
                        "foreign role policy attachment"
                    );
                }
                let inline = api.call("iam", "list-role-policies", json!({"RoleName":id}), &[])?;
                ensure!(no_token(&inline), "incomplete inline policy inventory");
                for name in array(&inline, "PolicyNames")? {
                    let saved = list
                        .iter()
                        .find(|r| {
                            r["type"] == "aws:iam/rolePolicy:RolePolicy"
                                && r["inputs"]["role"] == id
                                && r["inputs"]["name"] == *name
                        })
                        .context("foreign inline role policy")?;
                    let policy = api.call(
                        "iam",
                        "get-role-policy",
                        json!({"RoleName":id,"PolicyName":name}),
                        &[],
                    )?;
                    ensure!(
                        participant::canonical_policy(&policy["PolicyDocument"])?
                            == participant::canonical_policy(&serde_json::from_str(
                                saved["inputs"]["policy"]
                                    .as_str()
                                    .context("inline policy missing")?
                            )?)?,
                        "inline policy drift"
                    );
                }
            }
            "aws:iam/policy:Policy" => {
                let policy = match api.call("iam", "get-policy", json!({"PolicyArn":id}), &[]) {
                    Err(e)
                        if allow_missing
                            && missing(&e, &["NoSuchEntity", "NoSuchEntityException"]) =>
                    {
                        continue;
                    }
                    other => other?,
                };
                let saved = resource["outputs"]["policyId"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .context("checkpoint lacks immutable PolicyId")?;
                ensure!(
                    policy["Policy"]["PolicyId"] == saved
                        && policy["Policy"]["Arn"] == id
                        && policy["Policy"]["Path"] == resource["inputs"]["path"],
                    "managed policy incarnation changed"
                );
                for usage in ["PermissionsPolicy", "PermissionsBoundary"] {
                    let consumers = api.call(
                        "iam",
                        "list-entities-for-policy",
                        json!({"PolicyArn":id,"PolicyUsageFilter":usage}),
                        &[],
                    )?;
                    ensure!(
                        no_token(&consumers)
                            && array(&consumers, "PolicyUsers")?.is_empty()
                            && array(&consumers, "PolicyGroups")?.is_empty(),
                        "foreign managed policy consumers"
                    );
                    for role in array(&consumers, "PolicyRoles")? {
                        ensure!(
                            usage == "PermissionsPolicy"
                                && list.iter().any(|r| r["type"]
                                    == "aws:iam/rolePolicyAttachment:RolePolicyAttachment"
                                    && r["inputs"]["policyArn"] == id
                                    && r["inputs"]["role"] == role["RoleName"]),
                            "foreign policy role/boundary consumer"
                        );
                    }
                }
                let document = api.call(
                    "iam",
                    "get-policy-version",
                    json!({"PolicyArn":id,"VersionId":policy["Policy"]["DefaultVersionId"]}),
                    &[],
                )?;
                ensure!(
                    participant::canonical_policy(&document["PolicyVersion"]["Document"])?
                        == participant::canonical_policy(&serde_json::from_str(
                            resource["inputs"]["policy"]
                                .as_str()
                                .context("policy document missing")?
                        )?)?,
                    "managed policy drift"
                );
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.verify_access_absent")
)]
fn verify_access_absent(api: &dyn AwsApi, checkpoint: &Value) -> Result<()> {
    for resource in aws_resources(checkpoint)? {
        let id = &resource["id"];
        match resource["type"].as_str().unwrap_or_default() {
            "aws:iam/role:Role" => require_absent(
                api,
                "iam",
                "get-role",
                json!({"RoleName":id}),
                &["NoSuchEntity", "NoSuchEntityException"],
            )?,
            "aws:iam/policy:Policy" => require_absent(
                api,
                "iam",
                "get-policy",
                json!({"PolicyArn":id}),
                &["NoSuchEntity", "NoSuchEntityException"],
            )?,
            "aws:s3/bucketV2:BucketV2" => require_absent(
                api,
                "s3api",
                "head-bucket",
                json!({"Bucket":id}),
                &["NoSuchBucket", "404", "NotFound"],
            )?,
            "aws:ecr/repository:Repository" => require_absent(
                api,
                "ecr",
                "describe-repositories",
                json!({"repositoryNames":[id]}),
                &["RepositoryNotFoundException"],
            )?,
            "aws:codebuild/project:Project" => {
                let name = resource["inputs"]["name"]
                    .as_str()
                    .context("build project name missing")?;
                let value = api.call(
                    "codebuild",
                    "batch-get-projects",
                    json!({"names":[name]}),
                    &[],
                )?;
                ensure!(
                    array(&value, "projects")?.is_empty()
                        && value["projectsNotFound"] == json!([name]),
                    "build project still exists"
                );
            }
            "aws:cloudwatch/logGroup:LogGroup" => {
                let value = api.call(
                    "logs",
                    "describe-log-groups",
                    json!({"logGroupNamePrefix":id}),
                    &[],
                )?;
                ensure!(
                    no_token(&value)
                        && !array(&value, "logGroups")?
                            .iter()
                            .any(|g| g["logGroupName"] == *id),
                    "build logs still exist"
                );
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.check_builds")
)]
fn check_builds(api: &dyn AwsApi, build: &BuildInfrastructure, evidence: &Value) -> Result<()> {
    let list = match api.call(
        "codebuild",
        "list-builds-for-project",
        json!({"projectName":build.project_name}),
        &[],
    ) {
        Err(e) if missing(&e, &["ResourceNotFoundException"]) => {
            json!({"ids":array(evidence,"builds")?.iter().filter_map(|b| b.get("buildId").filter(|v| v.is_string())).collect::<Vec<_>>()})
        }
        other => other?,
    };
    ensure!(no_token(&list), "build history exceeds inspection bound");
    let ids = array(&list, "ids")?;
    let known: BTreeSet<_> = array(evidence, "builds")?
        .iter()
        .filter_map(|b| b["buildId"].as_str())
        .collect();
    ensure!(
        ids.len() <= 100
            && ids
                .iter()
                .all(|id| id.as_str().is_some_and(|s| known.contains(s))),
        "unreceipted build job"
    );
    if ids.is_empty() {
        return Ok(());
    }
    let value = api.call("codebuild", "batch-get-builds", json!({"ids":ids}), &[])?;
    ensure!(
        array(&value, "buildsNotFound")?.is_empty() && array(&value, "builds")?.len() == ids.len(),
        "incomplete build observations"
    );
    let mut seen = BTreeSet::new();
    for job in array(&value, "builds")? {
        ensure!(
            ids.contains(&job["id"])
                && seen.insert(job["id"].as_str().context("job ID missing")?)
                && job["projectName"] == build.project_name
                && (job["endTime"].is_number()
                    || job["endTime"].as_str().is_some_and(|s| !s.is_empty()))
                && job["buildStatus"].as_str().is_some_and(|s| [
                    "SUCCEEDED",
                    "FAILED",
                    "FAULT",
                    "STOPPED",
                    "TIMED_OUT"
                ]
                .contains(&s)),
            "active/unknown build job"
        );
    }
    Ok(())
}

fn bucket_input(team: &TeamDefinition, bucket: &str) -> Value {
    json!({"Bucket":bucket,"ExpectedBucketOwner":team.aws.account_id})
}

fn versions(api: &dyn AwsApi, team: &TeamDefinition, bucket: &str) -> Result<Vec<Value>> {
    bucket_versions(api, team, bucket, false)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.bucket_versions")
)]
fn bucket_versions(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    bucket: &str,
    allow_suspended: bool,
) -> Result<Vec<Value>> {
    let configuration = api.call(
        "s3api",
        "get-bucket-versioning",
        bucket_input(team, bucket),
        &[],
    )?;
    ensure!(
        (configuration["Status"] == "Enabled"
            || (allow_suspended && configuration["Status"] == "Suspended"))
            && configuration
                .get("MFADelete")
                .is_none_or(|v| v == "Disabled"),
        "bucket versioning or MFA deletion changed"
    );
    for (operation, absent) in [
        (
            "get-object-lock-configuration",
            "ObjectLockConfigurationNotFoundError",
        ),
        (
            "get-bucket-replication",
            "ReplicationConfigurationNotFoundError",
        ),
    ] {
        require_absent(
            api,
            "s3api",
            operation,
            bucket_input(team, bucket),
            &[absent],
        )?;
    }
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    let mut latest = BTreeMap::new();
    let mut markers = BTreeSet::new();
    let mut input = bucket_input(team, bucket);
    input["MaxKeys"] = json!(1000);
    for page in 0..MAX_S3_VERSION_PAGES {
        let value = api.call(
            "s3api",
            "list-object-versions",
            input.clone(),
            &["--no-paginate".into()],
        )?;
        for field in ["Versions", "DeleteMarkers"] {
            if let Some(items) = value.get(field) {
                for item in items.as_array().context("invalid S3 version inventory")? {
                    let key = item["Key"].as_str().context("S3 key missing")?;
                    let version = item["VersionId"]
                        .as_str()
                        .filter(|s| !s.is_empty() && *s != "null")
                        .context("immutable S3 version missing")?;
                    ensure!(
                        !key.is_empty()
                            && !key.split('/').any(|p| p == "..")
                            && seen.insert((key.to_owned(), version.to_owned())),
                        "invalid/duplicate S3 version"
                    );
                    let is_latest = item["IsLatest"]
                        .as_bool()
                        .context("S3 latest-version flag missing")?;
                    *latest.entry(key.to_owned()).or_insert(0usize) += usize::from(is_latest);
                    result.push(json!({"Key":key,"VersionId":version,"latest":item["IsLatest"],"marker":field == "DeleteMarkers"}));
                    ensure!(
                        result.len() <= MAX_S3_VERSIONS,
                        "S3 inventory exceeds 10000-version bound; no automatic purge"
                    );
                }
            }
        }
        let truncated = value["IsTruncated"]
            .as_bool()
            .context("S3 truncation flag missing")?;
        if !truncated {
            break;
        }
        ensure!(
            page + 1 < MAX_S3_VERSION_PAGES,
            "S3 inventory exceeds 100-page bound; no automatic purge"
        );
        let key = value["NextKeyMarker"]
            .as_str()
            .filter(|s| !s.is_empty())
            .context("S3 next key marker missing")?;
        let version = value["NextVersionIdMarker"]
            .as_str()
            .filter(|s| !s.is_empty() && *s != "null")
            .context("S3 next version marker missing")?;
        ensure!(
            seen.contains(&(key.to_owned(), version.to_owned()))
                && markers.insert((key.to_owned(), version.to_owned())),
            "invalid/repeated S3 continuation marker"
        );
        input["KeyMarker"] = json!(key);
        input["VersionIdMarker"] = json!(version);
    }
    ensure!(
        latest.values().all(|n| *n == 1),
        "incoherent S3 latest-version inventory"
    );
    let mut input = bucket_input(team, bucket);
    input["MaxUploads"] = json!(1);
    let uploads = api.call(
        "s3api",
        "list-multipart-uploads",
        input,
        &["--no-paginate".into()],
    )?;
    ensure!(
        uploads.get("IsTruncated").is_none_or(|v| v == false)
            && uploads
                .get("Uploads")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "multipart uploads remain; stop writers"
    );
    Ok(result)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.build_data")
)]
fn build_data(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    build: &BuildInfrastructure,
    evidence: &Value,
    deleted_configuration: (bool, bool),
) -> Result<Value> {
    let objects = match api.call(
        "s3api",
        "head-bucket",
        bucket_input(team, &build.source_bucket),
        &[],
    ) {
        Err(e) if missing(&e, &["NoSuchBucket", "404", "NotFound"]) => Vec::new(),
        Err(e) => return Err(e),
        Ok(_) => {
            let tags = api.call(
                "s3api",
                "get-bucket-tagging",
                bucket_input(team, &build.source_bucket),
                &[],
            )?;
            ensure!(
                tag_map(&tags["TagSet"], "Key", "Value")? == access::admin_tags(team),
                "build bucket ownership drift"
            );
            let policy = api.call(
                "s3api",
                "get-bucket-policy",
                bucket_input(team, &build.source_bucket),
                &[],
            );
            let expected = build.resources(team)?;
            match policy {
                Err(e) if deleted_configuration.0 && missing(&e, &["NoSuchBucketPolicy"]) => {}
                Err(e) => return Err(e),
                Ok(policy) => ensure!(
                    equivalent(
                        &policy["Policy"],
                        &expected["buildBucketPolicy"]["properties"]["policy"]
                    )?,
                    "build bucket policy has unexplained consumers"
                ),
            }
            let objects =
                bucket_versions(api, team, &build.source_bucket, deleted_configuration.1)?;
            ensure!(
                !(deleted_configuration.0 || deleted_configuration.1) || objects.is_empty(),
                "surviving build bucket must be empty after provider configuration deletion"
            );
            let known: BTreeSet<_> = array(evidence, "builds")?
                .iter()
                .flat_map(|b| b["keys"].as_array().into_iter().flatten())
                .filter_map(Value::as_str)
                .collect();
            for object in &objects {
                let key = object["Key"].as_str().unwrap();
                ensure!(
                    known.contains(key)
                        || (!array(evidence, "builds")?.is_empty()
                            && key.starts_with("cache/")
                            && key.len() > 6),
                    "unexplained build data"
                );
            }
            objects
        }
    };
    let images = match api.call(
        "ecr",
        "list-images",
        json!({"registryId":team.aws.account_id,"repositoryName":build.repository}),
        &[],
    ) {
        Err(e) if missing(&e, &["RepositoryNotFoundException"]) => Vec::new(),
        Err(e) => return Err(e),
        Ok(value) => {
            ensure!(no_token(&value), "ECR image inventory exceeds bound");
            let images = array(&value, "imageIds")?.to_vec();
            let known: BTreeSet<_> = array(evidence, "builds")?
                .iter()
                .filter_map(|b| b["imageDigest"].as_str())
                .collect();
            ensure!(
                images
                    .iter()
                    .all(|i| i["imageDigest"].as_str().is_some_and(|s| known.contains(s))),
                "unexplained ECR image"
            );
            images
        }
    };
    Ok(json!({"objects":objects,"images":images,"identity":build_identity(api,team,build)?}))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.build_identity")
)]
fn build_identity(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    build: &BuildInfrastructure,
) -> Result<Value> {
    let mut identity = serde_json::Map::new();
    let project = api.call(
        "codebuild",
        "batch-get-projects",
        json!({"names":[build.project_name]}),
        &[],
    )?;
    let projects = array(&project, "projects")?;
    if let [project] = projects {
        ensure!(
            tag_map(&project["tags"], "key", "value")? == access::admin_tags(team)
                && project["name"] == build.project_name
                && project["serviceRole"]
                    == format!(
                        "arn:aws:iam::{}:role{}{}",
                        team.aws.account_id,
                        access::admin_path(team),
                        build.project_name
                    )
                && project["arn"]
                    == format!(
                        "arn:aws:codebuild:{}:{}:project/{}",
                        team.aws.region, team.aws.account_id, build.project_name
                    )
                && project["cache"]
                    == json!({"type":"S3","location":format!("{}/cache",build.source_bucket),"cacheNamespace":build.project_name})
                && project["logsConfig"]["cloudWatchLogs"]["groupName"]
                    == format!("/aws/codebuild/{}", build.project_name)
                && !project["created"].is_null(),
            "CodeBuild ownership/linkage changed"
        );
        identity.insert("project".into(), project["created"].clone());
    } else {
        ensure!(
            projects.is_empty() && project["projectsNotFound"] == json!([build.project_name]),
            "unknown CodeBuild project"
        );
    }
    match api.call(
        "ecr",
        "describe-repositories",
        json!({"registryId":team.aws.account_id,"repositoryNames":[build.repository]}),
        &[],
    ) {
        Err(e) if missing(&e, &["RepositoryNotFoundException"]) => {}
        Err(e) => return Err(e),
        Ok(value) => {
            let repos = array(&value, "repositories")?;
            ensure!(repos.len() == 1, "unexpected ECR repositories");
            let repo = &repos[0];
            let arn = format!(
                "arn:aws:ecr:{}:{}:repository/{}",
                team.aws.region, team.aws.account_id, build.repository
            );
            ensure!(
                repo["repositoryArn"] == arn
                    && repo["repositoryName"] == build.repository
                    && repo["registryId"] == team.aws.account_id
                    && repo["repositoryUri"] == build.repository_uri
                    && !repo["createdAt"].is_null(),
                "ECR identity changed"
            );
            let tags = api.call(
                "ecr",
                "list-tags-for-resource",
                json!({"resourceArn":arn}),
                &[],
            )?;
            ensure!(
                tag_map(&tags["tags"], "Key", "Value")? == access::admin_tags(team),
                "ECR ownership changed"
            );
            require_absent(
                api,
                "ecr",
                "get-repository-policy",
                json!({"registryId":team.aws.account_id,"repositoryName":build.repository}),
                &["RepositoryPolicyNotFoundException"],
            )?;
            identity.insert("repository".into(), repo["createdAt"].clone());
        }
    }
    let name = format!("/aws/codebuild/{}", build.project_name);
    let logs = api.call(
        "logs",
        "describe-log-groups",
        json!({"logGroupNamePrefix":name}),
        &[],
    )?;
    ensure!(no_token(&logs), "incomplete build log inventory");
    for group in array(&logs, "logGroups")? {
        if group["logGroupName"] != name {
            continue;
        }
        ensure!(
            group["retentionInDays"] == 30 && !group["creationTime"].is_null(),
            "build log identity changed"
        );
        let tags = api.call(
            "logs",
            "list-tags-log-group",
            json!({"logGroupName":name}),
            &[],
        )?;
        ensure!(
            tags["tags"] == access::admin_tags(team),
            "build log ownership changed"
        );
        identity.insert("logs".into(), group["creationTime"].clone());
    }
    Ok(Value::Object(identity))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.purge_build_data")
)]
fn purge_build_data(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    build: &BuildInfrastructure,
    data: &Value,
) -> Result<()> {
    let objects = array(data, "objects")?;
    if !objects.is_empty() {
        purge_versions(api, team, &build.source_bucket, objects)?;
    }
    let images = array(data, "images")?;
    for chunk in images.chunks(100) {
        let result = api.call("ecr","batch-delete-image",json!({"registryId":team.aws.account_id,"repositoryName":build.repository,"imageIds":chunk}),&[])?;
        ensure!(
            array(&result, "failures")?.is_empty(),
            "ECR reported partial deletion failure"
        );
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.purge_versions")
)]
fn purge_versions(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    bucket: &str,
    objects: &[Value],
) -> Result<()> {
    // Delete old versions in a separate acknowledged phase. Otherwise a partial
    // batch could delete the current empty checkpoint/delete marker and expose
    // an older nonempty checkpoint or lock, preventing safe reconciliation.
    for latest in [false, true] {
        let phase: Vec<_> = objects.iter().filter(|v| v["latest"] == latest).collect();
        for chunk in phase.chunks(100) {
            let mut input = bucket_input(team, bucket);
            input["Delete"] = json!({"Objects":chunk.iter().map(|v| json!({"Key":v["Key"],"VersionId":v["VersionId"]})).collect::<Vec<_>>(),"Quiet":false});
            let result = api.call("s3api", "delete-objects", input, &[])?;
            ensure!(
                result
                    .get("Errors")
                    .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
                "S3 reported partial deletion failure"
            );
            let deleted = array(&result, "Deleted")?;
            let actual: BTreeSet<_> = deleted
                .iter()
                .map(|v| (v["Key"].as_str(), v["VersionId"].as_str()))
                .collect();
            ensure!(
                actual.len() == chunk.len()
                    && deleted.len() == chunk.len()
                    && chunk
                        .iter()
                        .all(|v| actual.contains(&(v["Key"].as_str(), v["VersionId"].as_str()))),
                "S3 version deletion acknowledgement is incomplete"
            );
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.ensure_subset")
)]
fn ensure_subset(saved: &[Value], current: &[Value]) -> Result<()> {
    ensure!(
        current
            .iter()
            .all(|v| saved.iter().any(|s| s["Key"] == v["Key"]
                && s["VersionId"] == v["VersionId"]
                && s["marker"] == v["marker"])),
        "new object versions appeared during removal; stop writers and inspect"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.backend_data")
)]
fn backend_data(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    evidence: &Value,
    access_active: bool,
) -> Result<Vec<Value>> {
    let policy = api.call(
        "s3api",
        "get-bucket-policy",
        bucket_input(team, team.backend_bucket()?),
        &[],
    )?;
    ensure!(
        participant::canonical_policy(&serde_json::from_str::<Value>(
            policy["Policy"]
                .as_str()
                .context("backend policy missing")?
        )?)? == participant::canonical_policy(&aws::tls_policy(team.backend_bucket()?))?,
        "backend policy has unexplained consumers"
    );
    let objects = versions(api, team, team.backend_bucket()?)?;
    let networks = evidence["networks"]
        .as_object()
        .context("network evidence missing")?;
    let admin_root = format!("zdn-admin/v1/{}/.pulumi/", team.bootstrap_id);
    let network_root = format!("{}/.pulumi/", team.backend_prefix()?);
    let mut stacks = vec![(
        admin_root.clone(),
        "zdn-access",
        format!("zdn-{}", team.bootstrap_id.simple()),
    )];
    for id in networks.keys() {
        stacks.push((
            network_root.clone(),
            "zdn-foundation",
            format!("zdn-{}", Uuid::parse_str(id)?.simple()),
        ));
        stacks.push((
            admin_root.clone(),
            "zdn-participant",
            format!("zdn-participant-{}", Uuid::parse_str(id)?.simple()),
        ));
    }
    for object in &objects {
        let key = object["Key"].as_str().unwrap();
        let mut allowed =
            key == format!("{admin_root}meta.yaml") || key == format!("{network_root}meta.yaml");
        for (root, project, stack) in &stacks {
            let checkpoint = format!("{root}stacks/{project}/{stack}.json");
            if key == checkpoint || key == format!("{checkpoint}.bak") {
                allowed = true;
                if object["latest"] == true
                    && object["marker"] == false
                    && !(access_active && *project == "zdn-access")
                {
                    // Exact immutable version, exact stack, empty resources and
                    // pending operations. No blanket .json.bak exception.
                    inspect_empty_checkpoint(
                        api,
                        team,
                        key,
                        object["VersionId"].as_str().unwrap(),
                        project,
                        stack,
                    )?;
                }
            }
            for kind in ["history", "backups"] {
                if key.starts_with(&format!("{root}{kind}/{project}/{stack}/")) {
                    allowed = true;
                }
            }
            if key.starts_with(&format!("{root}locks/organization/{project}/{stack}/")) {
                // Successful Pulumi operations leave versioned lock history.
                // Only a delete marker may be the current version of that key.
                ensure!(
                    object["latest"] != true || object["marker"] == true,
                    "current Pulumi lock remains; stop writers and investigate"
                );
                allowed = true;
            }
        }
        for (id, deployment) in networks {
            for name in ["reservation", "lease"] {
                if key == format!("{}/networks/{id}/{name}.json", team.metadata_prefix()) {
                    allowed = true;
                    if object["latest"] == true && object["marker"] == false {
                        let value =
                            read_object(api, team, key, object["VersionId"].as_str().unwrap())?;
                        if name == "reservation" {
                            let reservation: aws::NetworkReservation =
                                serde_json::from_value(value)?;
                            reservation.validate()?;
                            ensure!(
                                reservation.scope == team.scope()
                                    && reservation.network_id.to_string() == *id
                                    && serde_json::to_value(reservation.owner_id)?
                                        == deployment["owner_id"],
                                "foreign network reservation"
                            );
                        } else {
                            let lease: aws::LeaseRecord = serde_json::from_value(value)?;
                            lease.reservation.validate()?;
                            ensure!(
                                lease.version == 1
                                    && lease.generation > 0
                                    && lease.released
                                    && lease.reservation.scope == team.scope()
                                    && lease.reservation.network_id.to_string() == *id
                                    && serde_json::to_value(lease.reservation.owner_id)?
                                        == deployment["owner_id"],
                                "network lease is unreleased or has foreign ownership"
                            );
                        }
                    }
                }
            }
        }
        ensure!(
            allowed && !key.contains("/artifacts/"),
            "unknown/shared backend object or retained product data: {key}"
        );
    }
    Ok(objects)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.read_object")
)]
fn read_object(api: &dyn AwsApi, team: &TeamDefinition, key: &str, version: &str) -> Result<Value> {
    use std::io::Read;
    let file = tempfile::NamedTempFile::new()?;
    let response = api.call(
        "s3api",
        "get-object",
        json!({"Bucket":team.backend_bucket()?,"ExpectedBucketOwner":team.aws.account_id,
        "Key":key,"VersionId":version,"Range":"bytes=0-65536"}),
        &[file.path().to_string_lossy().into_owned()],
    )?;
    ensure!(
        response["VersionId"] == version,
        "inspected S3 version changed"
    );
    let mut bytes = Vec::new();
    fs::File::open(file.path())?
        .take(65537)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 65536,
        "state object exceeds inspection bound"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.inspect_empty_checkpoint")
)]
fn inspect_empty_checkpoint(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    key: &str,
    version: &str,
    project: &str,
    stack: &str,
) -> Result<()> {
    let value = read_object(api, team, key, version)?;
    ensure!(
        value["version"] == 3
            && value["checkpoint"]["stack"] == format!("organization/{project}/{stack}"),
        "unknown current checkpoint format/identity"
    );
    let latest = &value["checkpoint"]["latest"];
    ensure!(
        latest.is_object()
            && latest
                .get("resources")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
            && latest
                .get("pending_operations")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "current checkpoint still contains resources or pending operations"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "removal.team.check_key")
)]
fn check_key(api: &dyn AwsApi, team: &TeamDefinition, allow_pending: bool) -> Result<Value> {
    let value = api.call(
        "kms",
        "describe-key",
        json!({"KeyId":team.state.kms_key_arn}),
        &[],
    )?;
    let key = &value["KeyMetadata"];
    ensure!(
        key["Arn"] == team.state.kms_key_arn
            && key["AWSAccountId"] == team.aws.account_id
            && key["KeyManager"] == "CUSTOMER"
            && key["KeySpec"] == "SYMMETRIC_DEFAULT"
            && key["KeyUsage"] == "ENCRYPT_DECRYPT"
            && key.get("MultiRegion").is_none_or(|v| v == false)
            && (key["KeyState"] == "Enabled"
                || (allow_pending && key["KeyState"] == "PendingDeletion")),
        "KMS identity or state changed"
    );
    let tags = api.call(
        "kms",
        "list-resource-tags",
        json!({"KeyId":team.state.kms_key_arn}),
        &[],
    )?;
    ensure!(
        tags.get("Truncated").is_none_or(|v| v == false)
            && tag_map(&tags["Tags"], "TagKey", "TagValue")?
                == json!({"zdn:project":"zdn","zdn:team":team.team_id,"zdn:bootstrap":team.bootstrap_id}),
        "KMS ownership changed"
    );
    for (operation, field) in [("list-aliases", "Aliases"), ("list-grants", "Grants")] {
        let value = api.call(
            "kms",
            operation,
            json!({"KeyId":team.state.kms_key_arn}),
            &[],
        )?;
        ensure!(
            no_token(&value)
                && value.get("Truncated").is_none_or(|v| v == false)
                && array(&value, field)?.is_empty(),
            "KMS aliases/grants require explicit external handling"
        );
    }
    let policy = api.call(
        "kms",
        "get-key-policy",
        json!({"KeyId":team.state.kms_key_arn,"PolicyName":"default"}),
        &[],
    )?;
    let expected = json!({"Version":"2012-10-17","Id":"key-default-1","Statement":[{"Sid":"Enable IAM User Permissions","Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{}:root",team.aws.account_id)},"Action":"kms:*","Resource":"*"}]});
    ensure!(
        participant::canonical_policy(&serde_json::from_str(
            policy["Policy"].as_str().context("KMS policy missing")?
        )?)? == participant::canonical_policy(&expected)?,
        "KMS policy has unexplained consumers"
    );
    Ok(key.clone())
}
