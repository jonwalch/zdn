use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use uuid::Uuid;
use zdn::state::{BindingContext, Reservation, Scope, StateLockBusy, StateStore};

fn scope() -> Scope {
    Scope {
        team_id: "test-team".into(),
        account_id: "123456789012".into(),
        region: "us-east-1".into(),
    }
}

fn id(suffix: u8) -> Uuid {
    Uuid::parse_str(&format!("a81c4e9b-0000-4000-8000-{suffix:012}")).unwrap()
}

fn context(path: &Path, branch: &str) -> BindingContext {
    BindingContext::new(
        path.join("devnet.yaml"),
        Some(path.to_path_buf()),
        Some(branch.into()),
        scope(),
    )
    .unwrap()
}

fn fixture() -> (TempDir, PathBuf, StateStore) {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("devnet.yaml"), "name: my-feature\n").unwrap();
    let store = StateStore::open(temp.path().join("state")).unwrap();
    (temp, source, store)
}

#[test]
fn rename_preserves_identity_and_all_resource_names() {
    let (_temp, source, store) = fixture();
    let context = context(&source, "branch-a");
    let first = store.bind_with_id(&context, "feature", || id(1)).unwrap();
    let renamed = store
        .bind_with_id(&context, "renamed", || panic!("must reuse saved ID"))
        .unwrap();
    assert_eq!(first.network_id, renamed.network_id);
    assert_eq!(first.context_key, renamed.context_key);
    assert_eq!(renamed.reservation, Reservation::Unreserved);
    assert_eq!(
        first.resource_name("node-1", 63).unwrap(),
        renamed.resource_name("node-1", 63).unwrap()
    );
    assert!(renamed.resource_name("node-1", 20).is_err());
    assert!(renamed.resource_name("../other", 63).is_err());
    assert_eq!(renamed.display_name(), "renamed-a81c4e9b");
    assert_eq!(
        StateStore::open(store.root())
            .unwrap()
            .binding(&context)
            .unwrap(),
        renamed
    );
}

#[test]
fn complete_context_separates_ids_and_missing_bindings_require_explicit_creation() {
    let (_temp, source, store) = fixture();
    let first = context(&source, "branch-a");
    let mut contexts = vec![context(&source, "branch-b")];
    for field in ["team", "account", "region", "path", "worktree"] {
        let mut changed = first.clone();
        match field {
            "team" => changed.scope.team_id = "other-team".into(),
            "account" => changed.scope.account_id = "999999999999".into(),
            "region" => changed.scope.region = "eu-west-1".into(),
            "path" => changed.config_path = source.join("second.yaml"),
            "worktree" => changed.worktree = Some(source.join("nested-worktree")),
            _ => unreachable!(),
        }
        contexts.push(changed);
    }
    let saved = store.bind_with_id(&first, "feature", || id(1)).unwrap();
    for (index, changed) in contexts.iter().enumerate() {
        assert!(store
            .binding(changed)
            .unwrap_err()
            .to_string()
            .contains("explicitly attach"));
        let new = store
            .bind_with_id(changed, "feature", || id(index as u8 + 2))
            .unwrap();
        assert_ne!(new.network_id, saved.network_id);
        assert_ne!(new.context_key, saved.context_key);
    }
}

#[test]
fn ambiguous_names_and_prefixes_show_full_ids_and_current_label_is_scoped() {
    let (_temp, source, store) = fixture();
    let first_context = context(&source, "branch-a");
    let second_context = context(&source, "branch-b");
    let first = store
        .bind_with_id(&first_context, "feature", || id(1))
        .unwrap();
    let second = store
        .bind_with_id(&second_context, "feature", || id(2))
        .unwrap();
    for selector in ["feature", "a81c4e9b"] {
        let error = store
            .resolve(&scope(), selector, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("ambiguous"));
        assert!(error.contains(&first.network_id.to_string()));
        assert!(error.contains(&second.network_id.to_string()));
    }
    assert_eq!(
        store
            .resolve(&scope(), "feature", Some(&first_context))
            .unwrap()
            .network_id,
        first.network_id
    );
    assert_eq!(
        store
            .resolve(
                &scope(),
                &second.network_id.to_string(),
                Some(&first_context)
            )
            .unwrap()
            .network_id,
        second.network_id
    );
    let mut wrong_scope = scope();
    wrong_scope.region = "eu-west-1".into();
    assert!(store
        .resolve(&wrong_scope, "feature", Some(&first_context))
        .is_err());
}

#[test]
fn a_uuid_shaped_label_cannot_redirect_an_explicit_full_id() {
    let (_temp, source, store) = fixture();
    let first_context = context(&source, "branch-a");
    let second_context = context(&source, "branch-b");
    store
        .bind_with_id(&first_context, &id(2).to_string(), || id(1))
        .unwrap();
    store
        .bind_with_id(&second_context, "target", || id(2))
        .unwrap();
    assert_eq!(
        store
            .resolve(&scope(), &id(2).to_string(), Some(&first_context))
            .unwrap()
            .network_id,
        id(2)
    );
    assert_eq!(
        store
            .resolve(&scope(), &id(2).to_string().to_uppercase(), None)
            .unwrap()
            .network_id,
        id(2)
    );
}

#[test]
fn explicit_receipt_attachment_checks_scope_and_id_and_deduplicates_resolution() {
    let (_temp, source, store) = fixture();
    let first_context = context(&source, "branch-a");
    let second_context = context(&source, "branch-b");
    let binding = store
        .bind_with_id(&first_context, "feature", || id(1))
        .unwrap();
    let export = binding.to_export();
    assert!(store.attach(&second_context, id(2), &export).is_err());
    for field in ["team", "account", "region"] {
        let mut wrong = export.clone();
        match field {
            "team" => wrong.scope.team_id = "other".into(),
            "account" => wrong.scope.account_id = "999999999999".into(),
            "region" => wrong.scope.region = "eu-west-1".into(),
            _ => unreachable!(),
        }
        assert!(store.attach(&second_context, id(1), &wrong).is_err());
    }
    let attached = store.attach(&second_context, id(1), &export).unwrap();
    assert_eq!(attached.network_id, binding.network_id);
    assert_ne!(attached.context_key, binding.context_key);
    assert_eq!(
        store.resolve(&scope(), "feature", None).unwrap().network_id,
        id(1)
    );
    let mut wrong_version = export.clone();
    wrong_version.version = 99;
    assert!(store
        .attach(&context(&source, "branch-c"), id(1), &wrong_version)
        .is_err());
    let another = store
        .bind_with_id(&context(&source, "branch-c"), "other", || id(3))
        .unwrap();
    assert!(store
        .attach(&second_context, id(3), &another.to_export())
        .is_err());
    let mut changed_scope_context = context(&source, "another-scope");
    changed_scope_context.scope.team_id = "another-team".into();
    let mut changed_scope_receipt = export;
    changed_scope_receipt.scope = changed_scope_context.scope.clone();
    assert!(store
        .attach(&changed_scope_context, id(1), &changed_scope_receipt)
        .is_err());
}

#[test]
fn snapshots_are_scoped_owned_fresh_and_validate_foreign_records() {
    let (_temp, source, store) = fixture();
    assert_eq!(store.snapshot(&scope()).unwrap(), (vec![], vec![]));
    let binding = store
        .bind(&context(&source, "selected"), "selected")
        .unwrap();
    let mut foreign_context = context(&source, "foreign");
    foreign_context.scope.team_id = "foreign-team".into();
    let foreign = store.bind(&foreign_context, "foreign").unwrap();
    let inputs = zdn::state::OperationInput {
        config_sha256: "a".repeat(64),
        source_manifest_sha256: None,
        archive_sha256: None,
    };
    let operation = store
        .begin_operation(&binding, "up", inputs.clone(), &["apply"])
        .unwrap();
    let foreign_operation = store
        .begin_operation(&foreign, "up", inputs, &["apply"])
        .unwrap();
    let saved = store.snapshot(&scope()).unwrap();
    assert_eq!(saved, (vec![binding.clone()], vec![operation.clone()]));
    let cancelled = store
        .request_cancel(operation.operation_id, operation.revision)
        .unwrap();
    assert_eq!(
        store.snapshot(&scope()).unwrap(),
        (vec![binding], vec![cancelled])
    );
    assert!(!saved.1[0].cancel_requested);
    assert_eq!(
        store.snapshot(&foreign_context.scope).unwrap(),
        (vec![foreign], vec![foreign_operation.clone()])
    );

    let path = store.root().join("state.json");
    let mut ledger: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let receipt = ledger["operations"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|receipt| receipt["operation_id"] == foreign_operation.operation_id.to_string())
        .unwrap();
    receipt["inputs"]["config_sha256"] = serde_json::json!("invalid");
    let corrupt = serde_json::to_vec(&ledger).unwrap();
    fs::write(&path, &corrupt).unwrap();
    assert!(store.snapshot(&scope()).is_err());
    assert_eq!(fs::read(path).unwrap(), corrupt);
}

#[test]
fn state_is_outside_source_and_has_private_permissions() {
    let (_temp, source, store) = fixture();
    let context = context(&source, "branch-a");
    assert!(StateStore::open(source.join("state"))
        .unwrap()
        .bind(&context, "feature")
        .is_err());
    store.bind(&context, "feature").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(store.root()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in ["state.json", "store.lock"] {
            assert_eq!(
                fs::metadata(store.root().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn opening_state_never_changes_existing_directory_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let documents = temp.path().join("Documents");
    fs::create_dir(&documents).unwrap();
    fs::set_permissions(&documents, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(documents.join("existing-file"), "keep this file").unwrap();
    let before = fs::metadata(&documents).unwrap().permissions().mode();

    let error = StateStore::open(&documents).unwrap_err();
    assert!(error.to_string().contains("dedicated private --state-dir"));
    assert!(!error.is::<StateLockBusy>());
    assert_eq!(
        fs::metadata(&documents).unwrap().permissions().mode(),
        before
    );
    assert_eq!(fs::read_dir(&documents).unwrap().count(), 1);
    assert_eq!(
        fs::read_to_string(documents.join("existing-file")).unwrap(),
        "keep this file"
    );

    let store = StateStore::open(documents.join("zdn").join("state")).unwrap();
    assert_eq!(
        fs::metadata(&documents).unwrap().permissions().mode(),
        before
    );
    for created in [documents.join("zdn"), store.root().to_path_buf()] {
        assert_eq!(
            fs::metadata(created).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    StateStore::open(store.root()).unwrap();
}

#[cfg(unix)]
#[test]
fn existing_managed_state_with_changed_permissions_requires_explicit_repair() {
    use std::os::unix::fs::PermissionsExt;

    let (_temp, source, store) = fixture();
    let context = context(&source, "main");
    let binding = store.bind(&context, "feature").unwrap();
    let before = fs::read(store.root().join("state.json")).unwrap();
    fs::set_permissions(store.root(), fs::Permissions::from_mode(0o770)).unwrap();

    assert!(StateStore::open(store.root()).is_err());
    assert!(store.bind(&context, "changed").is_err());
    assert_eq!(
        fs::metadata(store.root()).unwrap().permissions().mode() & 0o777,
        0o770
    );
    assert_eq!(fs::read(store.root().join("state.json")).unwrap(), before);

    fs::set_permissions(store.root(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        StateStore::open(store.root())
            .unwrap()
            .binding(&context)
            .unwrap(),
        binding
    );
}

#[test]
fn separate_configuration_and_source_boundaries_preserve_existing_bindings() {
    let (temp, source, permitted_store) = fixture();
    let configuration = temp.path().join("configuration");
    fs::create_dir(&configuration).unwrap();
    fs::write(configuration.join("devnet.yaml"), "name: feature\n").unwrap();
    let split_context = BindingContext::new(
        configuration.join("devnet.yaml"),
        Some(source.clone()),
        Some("branch-a".into()),
        scope(),
    )
    .unwrap();
    let permitted = permitted_store
        .bind_with_id(&split_context, "feature", || id(1))
        .unwrap();
    assert_eq!(permitted_store.binding(&split_context).unwrap(), permitted);

    // A different context can already have legitimate bindings in the store.
    // Reject a newly selected forbidden context before changing those bindings.
    let saved_configuration = temp.path().join("saved-configuration");
    fs::create_dir(&saved_configuration).unwrap();
    fs::write(saved_configuration.join("devnet.yaml"), "name: saved\n").unwrap();
    let saved_context =
        BindingContext::new(saved_configuration.join("devnet.yaml"), None, None, scope()).unwrap();
    for forbidden_root in [
        configuration.clone(),
        configuration.join("state"),
        source.clone(),
        source.join("state"),
    ] {
        #[cfg(unix)]
        if forbidden_root.exists() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&forbidden_root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store = StateStore::open(forbidden_root).unwrap();
        let saved = store
            .bind_with_id(&saved_context, "saved", || id(2))
            .unwrap();
        let before = fs::read(store.root().join("state.json")).unwrap();
        assert!(store
            .bind(&split_context, "feature")
            .unwrap_err()
            .to_string()
            .contains("outside the configuration source directory and Git worktree"));
        assert!(store.binding(&split_context).is_err());
        assert!(store
            .attach(&split_context, permitted.network_id, &permitted.to_export())
            .is_err());
        assert!(store
            .resolve(&scope(), "saved", Some(&split_context))
            .is_err());
        assert_eq!(fs::read(store.root().join("state.json")).unwrap(), before);
        assert_eq!(store.binding(&saved_context).unwrap(), saved);
    }
}

#[cfg(unix)]
#[test]
fn boundary_checks_use_resolved_state_parent_paths() {
    use std::os::unix::fs::symlink;
    let (temp, source, _store) = fixture();
    let configuration = temp.path().join("configuration");
    fs::create_dir(&configuration).unwrap();
    fs::write(configuration.join("devnet.yaml"), "name: feature\n").unwrap();
    let context = BindingContext::new(
        configuration.join("devnet.yaml"),
        Some(source.clone()),
        Some("branch-a".into()),
        scope(),
    )
    .unwrap();
    for (name, target) in [("config-link", configuration), ("source-link", source)] {
        let link = temp.path().join(name);
        symlink(target, &link).unwrap();
        let store = StateStore::open(link.join("state")).unwrap();
        assert!(store.bind(&context, "feature").is_err());
        assert!(!store.root().join("state.json").exists());
        assert!(!store.root().join("store.lock").exists());
    }
}

#[cfg(unix)]
#[test]
fn symlinked_state_root_lock_and_ledger_are_rejected_without_touching_targets() {
    use std::os::unix::fs::symlink;
    let (temp, source, store) = fixture();
    let context = context(&source, "branch-a");
    let outside = temp.path().join("outside");
    fs::write(&outside, "keep me").unwrap();
    let link = temp.path().join("linked-root");
    symlink(store.root(), &link).unwrap();
    assert!(StateStore::open(&link).is_err());
    symlink(&outside, store.root().join("store.lock")).unwrap();
    assert!(store.bind(&context, "feature").is_err());
    fs::remove_file(store.root().join("store.lock")).unwrap();
    symlink(&outside, store.root().join("state.json")).unwrap();
    assert!(store.bind(&context, "feature").is_err());
    assert!(store.snapshot(&scope()).is_err());
    assert_eq!(fs::read_to_string(outside).unwrap(), "keep me");
}

#[test]
fn malformed_or_unsupported_state_is_preserved_instead_of_reset() {
    let (_temp, source, store) = fixture();
    let context = context(&source, "branch-a");
    store.bind_with_id(&context, "feature", || id(1)).unwrap();
    let path = store.root().join("state.json");
    let saved = fs::read(&path).unwrap();
    for content in [
        b"{broken".to_vec(),
        b"{\"version\":99,\"bindings\":[],\"operations\":[]}".to_vec(),
    ] {
        fs::write(&path, &content).unwrap();
        assert!(store.bind(&context, "renamed").is_err());
        assert!(store.snapshot(&scope()).is_err());
        assert_eq!(fs::read(&path).unwrap(), content);
    }
    fs::write(&path, saved).unwrap();
    assert_eq!(store.binding(&context).unwrap().label, "feature");
}

#[test]
fn a_held_process_lock_returns_busy_without_overwriting_state() {
    let (_temp, source, store) = fixture();
    let context = context(&source, "main");
    let binding = store.bind(&context, "feature").unwrap();
    let before = fs::read(store.root().join("state.json")).unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(store.root().join("store.lock"))
        .unwrap();
    fs2::FileExt::lock_exclusive(&lock).unwrap();
    let bounded = store.clone().with_lock_timeout(Duration::ZERO);
    let error = bounded.bind(&context, "rename").unwrap_err();
    assert!(error.is::<StateLockBusy>());
    assert!(error.to_string().contains("state is busy"));
    assert!(bounded
        .snapshot(&scope())
        .unwrap_err()
        .is::<StateLockBusy>());
    assert_eq!(fs::read(store.root().join("state.json")).unwrap(), before);
    fs2::FileExt::unlock(&lock).unwrap();
    assert_eq!(store.snapshot(&scope()).unwrap().0, vec![binding.clone()]);
    assert_eq!(store.binding(&context).unwrap(), binding);
}

fn start_worker(source: &Path, state: &Path, branch: &str, suffix: u8) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "binding_process_worker", "--nocapture"])
        .env("ZDN_BIND_WORKER_SOURCE", source)
        .env("ZDN_BIND_WORKER_STATE", state)
        .env("ZDN_BIND_WORKER_BRANCH", branch)
        .env("ZDN_BIND_WORKER_ID", suffix.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

fn await_ready(child: &mut Child) {
    let mut output = BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert_ne!(
            output.read_line(&mut line).unwrap(),
            0,
            "worker exited before ready"
        );
        if line.contains("BIND_READY") {
            break;
        }
    }
    // Keep stdout drained and open until process exit; its test harness prints completion.
    std::thread::spawn(move || {
        let mut discard = Vec::new();
        output.read_to_end(&mut discard).unwrap();
    });
}

#[test]
fn concurrent_processes_reuse_one_context_id_and_preserve_distinct_contexts() {
    let (_temp, source, store) = fixture();
    for (first_branch, second_branch, first_id, second_id) in
        [("same", "same", 1, 2), ("different-a", "different-b", 3, 4)]
    {
        let mut first = start_worker(&source, store.root(), first_branch, first_id);
        let mut second = start_worker(&source, store.root(), second_branch, second_id);
        await_ready(&mut first);
        await_ready(&mut second);
        first.stdin.take().unwrap().write_all(b"go\n").unwrap();
        second.stdin.take().unwrap().write_all(b"go\n").unwrap();
        assert!(first.wait().unwrap().success());
        assert!(second.wait().unwrap().success());
    }
    assert_eq!(store.list(&scope()).unwrap().len(), 3);
    assert_eq!(
        store
            .binding(&context(&source, "different-a"))
            .unwrap()
            .network_id,
        id(3)
    );
    assert_eq!(
        store
            .binding(&context(&source, "different-b"))
            .unwrap()
            .network_id,
        id(4)
    );
    assert!([id(1), id(2)].contains(&store.binding(&context(&source, "same")).unwrap().network_id));
}

#[test]
fn binding_process_worker() {
    let Ok(source) = std::env::var("ZDN_BIND_WORKER_SOURCE") else {
        return;
    };
    let state = std::env::var("ZDN_BIND_WORKER_STATE").unwrap();
    let branch = std::env::var("ZDN_BIND_WORKER_BRANCH").unwrap();
    let suffix = std::env::var("ZDN_BIND_WORKER_ID")
        .unwrap()
        .parse()
        .unwrap();
    println!("BIND_READY");
    std::io::stdout().flush().unwrap();
    let mut start = String::new();
    std::io::stdin().read_line(&mut start).unwrap();
    StateStore::open(state)
        .unwrap()
        .bind_with_id(&context(Path::new(&source), &branch), "feature", || {
            id(suffix)
        })
        .unwrap();
}
