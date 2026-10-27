use super::*;
use zdn::{
    participant::ParticipantReceipt,
    removal::{self, RemovalClient, RemovalStack},
};

#[derive(Args)]
pub struct ParticipantRemovalArgs {
    /// Original participants/BOOTSTRAP-ID/NETWORK-ID directory, never an imported endpoint file.
    #[arg(long)]
    receipt_dir: PathBuf,
    #[command(flatten)]
    managed: ManagedArgs,
    /// Explicit alias for the default offline, read-only proposal.
    #[arg(long, conflicts_with = "yes")]
    plan: bool,
    /// Destructively remove this exact owned grant.
    #[arg(long)]
    yes: bool,
    /// Re-observe an interrupted removal. Never refresh/adopt replacement resources.
    #[arg(long, requires = "yes")]
    reconcile: bool,
    /// Profile with still-valid cached STS credentials issued to this participant role before deletion.
    #[arg(long, requires = "yes")]
    revocation_profile: Option<String>,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.removal.participant")
)]
pub(super) fn participant(args: ParticipantRemovalArgs) -> Result<()> {
    let proposal = removal::participant_plan(&args.receipt_dir)?;
    if !args.yes {
        return print_json(&proposal);
    }
    let receipt: ParticipantReceipt =
        foundation::read_json(&args.receipt_dir.join("participant.json"))?;
    let api = AwsCli::new(receipt.request.administrator.clone())?;
    let probe = args
        .revocation_profile
        .map(|profile| {
            let mut selection = receipt.request.administrator.clone();
            selection.profile = profile;
            AwsCli::new(selection)
        })
        .transpose()?;
    let managed = data_path(args.managed.managed_dir, "tools")?;
    let stack = zdn::participant::live_stack(
        &receipt.request,
        &args.receipt_dir,
        &managed,
        cancellation()?,
    )?;
    let mut stack = RemovalClient {
        client: stack.client,
        cancel: stack.cancel,
    };
    print_json(&removal::remove_participant(
        &api,
        &args.receipt_dir,
        &mut stack,
        args.reconcile,
        probe.as_ref().map(|p| p as &dyn aws::AwsApi),
    )?)
}

#[derive(Args)]
pub struct TeamRemovalArgs {
    #[command(flatten)]
    store: StoreArgs,
    /// Saved local ZDN profile whose ORIGINAL bootstrap creation receipts establish ownership.
    #[arg(long, default_value = "devnet")]
    profile: String,
    /// Original administrator AWS profile (not the developer deployment role).
    #[arg(long)]
    aws_profile: String,
    #[command(flatten)]
    managed: ManagedArgs,
    /// Explicit offline proposal (also the default without --yes); conflicts with --yes and deletes nothing.
    #[arg(long, conflicts_with = "yes")]
    plan: bool,
    /// Destructive apply; requires --delete-data and --writers-stopped after network/data/participant cleanup. Inspect the default proposal first.
    #[arg(long, requires_all = ["delete_data", "writers_stopped"])]
    yes: bool,
    /// Consent to delete exact owned build images/data and backend versions/history.
    #[arg(long)]
    delete_data: bool,
    /// Attest that every other controller, build submitter and data writer has stopped.
    #[arg(long)]
    writers_stopped: bool,
    /// Reobserve interrupted removal without adopting replacement resources; requires the same --yes deletion consent.
    #[arg(long, requires = "yes")]
    reconcile: bool,
    /// Stop after owned administrator/build removal; preserve backend and enabled KMS for inspection.
    #[arg(long)]
    keep_backend: bool,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.removal.team")
)]
pub(super) fn team(args: TeamRemovalArgs) -> Result<()> {
    let store = open_store(args.store)?;
    let path = profile_path(&store, &args.profile)?;
    let proposal = removal::team_plan(&path)?;
    if !args.yes {
        return print_json(&proposal);
    }
    let _profile_lock = profile_lock(&path)?;
    let local = load_profile(&store, &args.profile)?;
    let selection = aws::AwsSelection {
        profile: args.aws_profile,
        account_id: local.team.aws.account_id.clone(),
        region: local.team.aws.region.clone(),
    };
    let api = AwsCli::new(selection.clone())?;
    let directory = path.with_extension("access");
    let mut stack = if proposal["managedAdministratorStack"] == true {
        let creation: access_bootstrap::AccessReceipt =
            foundation::read_json(&directory.join("access.json"))?;
        let managed = data_path(args.managed.managed_dir, "tools")?;
        let stack =
            access_bootstrap::live_stack(&creation.request, &directory, &managed, cancellation()?)?;
        Some(RemovalClient {
            client: stack.client,
            cancel: stack.cancel,
        })
    } else {
        None
    };
    print_json(&removal::remove_team(
        &api,
        &selection,
        store.root(),
        &path,
        stack.as_mut().map(|s| s as &mut dyn RemovalStack),
        &removal::TeamRemovalOptions {
            delete_data: args.delete_data,
            writers_stopped: args.writers_stopped,
            reconcile: args.reconcile,
            keep_backend: args.keep_backend,
        },
    )?)
}
