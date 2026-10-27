//! Offline immutable native installer and command binding; no cloud calls.
use super::*;

mod fixture {
    use crate as zdn;
    include!("../../../tests/support/lightwallet_service.rs");
}

fn spec() -> crate::lightwallet_service::LightwalletInstallSpec {
    let (host, service) = fixture::specs();
    let artifact = |name: &str| {
        let mut object = host.helper.clone();
        object.key = format!("team/test/{name}");
        object
    };
    crate::lightwallet_service::LightwalletInstallSpec {
        api_version: crate::lightwallet_service::INSTALL_API_VERSION.into(),
        image_record: artifact("lightwallet-image.json"),
        image_manifest: artifact("lightwallet-image-manifest.json"),
        image_config: artifact("lightwallet-image-config.json"),
        new_volume: Some(crate::host::NewVolumeAuthorization {
            api_version: crate::host::NEW_VOLUME_API_VERSION.into(),
            volume_id: service.cache_volume_id.clone(),
            instance_id: "i-0123456789abcdef0".into(),
            created_at: "2026-10-16T12:00:00Z".into(),
            size_bytes: service.cache_bytes,
            creation_intent_sha256: "d".repeat(64),
            checkpoint_sha256: "e".repeat(64),
        }),
        host,
        service,
    }
}

#[test]
fn explicit_native_recipes_require_exact_saved_bytes_and_protocol() {
    let spec = spec();
    let root = tempfile::tempdir().unwrap();
    let directory = root.path();
    let protocol = Some(crate::host::runtime::PROTOCOL);
    let node = selected_node(directory, &spec.host, protocol).unwrap();
    let lightwallet = selected_lightwallet(directory, &spec, protocol).unwrap();
    let gateway = selected_gateway(directory, &spec.host, protocol).unwrap();
    let manifest = native::node_manifest(protocol, &spec.host).unwrap();
    let report = crate::client_gateway::native::observation(&manifest, "ready").unwrap();
    native::validate_gateway_observation(protocol, &spec.host, &report).unwrap();
    assert!(native::validate_gateway_observation(None, &spec.host, &report).is_err());
    assert_eq!(node.install_sha256, spec.host.install_sha256().unwrap());
    assert_eq!(
        lightwallet.install_sha256,
        devnet::sha256(&serde_json::to_vec(&spec).unwrap())
    );
    for (stem, script) in [
        ("node-2", &node.script),
        ("lightwallet", &lightwallet.script),
        ("client-rpc", &gateway.script),
    ] {
        assert!(!script.contains("python"));
        std::fs::write(directory.join(format!("{stem}-install.sh")), script).unwrap();
    }
    assert_eq!(
        selected_node(directory, &spec.host, protocol)
            .unwrap()
            .script,
        node.script
    );
    assert_eq!(
        selected_lightwallet(directory, &spec, protocol)
            .unwrap()
            .script,
        lightwallet.script
    );
    assert_eq!(
        selected_gateway(directory, &spec.host, protocol)
            .unwrap()
            .script,
        gateway.script
    );
    for unsupported in [None, Some("foreign-runtime/v1")] {
        assert!(selected_node(directory, &spec.host, unsupported).is_err());
        assert!(selected_lightwallet(directory, &spec, unsupported).is_err());
        assert!(selected_gateway(directory, &spec.host, unsupported).is_err());
    }
    // Matching an embedded identity is not enough: the entire recipe is immutable.
    for stem in ["node-2", "lightwallet", "client-rpc"] {
        let path = directory.join(format!("{stem}-install.sh"));
        let original = std::fs::read(&path).unwrap();
        let mut tampered = original.clone();
        tampered.extend_from_slice(b"\nopaque foreign bytes\n");
        std::fs::write(&path, tampered).unwrap();
        assert!(selected_lightwallet(directory, &spec, protocol).is_err() || stem == "client-rpc");
        assert!(
            selected_gateway(directory, &spec.host, protocol).is_err() || stem == "lightwallet"
        );
        std::fs::write(path, original).unwrap();
    }
    let mut changed = spec.host.clone();
    changed.cpu_millis += 1;
    assert!(selected_node(directory, &changed, protocol).is_err());
    std::fs::write(
        directory.join("node-2-install.sh"),
        b"opaque foreign installer",
    )
    .unwrap();
    assert!(selected_node(directory, &spec.host, protocol).is_err());
    assert!(selected_gateway(directory, &spec.host, protocol).is_err());
    assert!(selected_lightwallet(directory, &spec, protocol).is_err());
}

#[test]
fn native_observations_cannot_reuse_foreign_command_history() {
    let spec = spec();
    let native =
        native::node_command(Some(crate::host::runtime::PROTOCOL), &spec.host, "observe").unwrap();
    let instance = "i-0123456789abcdef0";
    let foreign = "opaque foreign observation";
    let request = json!({"DocumentName":"AWS-RunShellScript","DocumentVersion":"1","InstanceIds":[instance],
        "TimeoutSeconds":120,"MaxConcurrency":"1","MaxErrors":"0","CloudWatchOutputConfig":{"CloudWatchOutputEnabled":false},
        "Parameters":{"commands":[foreign],"executionTimeout":[NODE_OBSERVATION_TIMEOUT.to_string()],"workingDirectory":["/"]}});
    let id = Uuid::new_v4();
    let journal = json!({"apiVersion":crate::ssm::API_VERSION,"requestSha256":devnet::sha256(&serde_json::to_vec(&request).unwrap()),
        "instanceId":instance,"timeoutSecs":NODE_OBSERVATION_TIMEOUT,"attempts":[{"id":id,"createdAt":1,"comment":format!("zdn-command-{id}"),
        "commandId":Uuid::new_v4().to_string(),"state":"succeeded","uncertain":false,"cancellationRequested":false,"failure":null,"output":{}}]});
    let bytes = serde_json::to_vec(&journal).unwrap();
    crate::ssm::validate_handoff_request(
        &bytes,
        instance,
        foreign,
        NODE_OBSERVATION_TIMEOUT,
        false,
    )
    .unwrap();
    assert!(crate::ssm::validate_handoff_request(
        &bytes,
        instance,
        &native,
        NODE_OBSERVATION_TIMEOUT,
        false
    )
    .is_err());
}

#[test]
fn native_installer_fetch_history_is_bound_to_protocol_and_request() {
    let mut deployment = super::producer_tests::fixture_deployment();
    deployment
        .cluster
        .as_mut()
        .unwrap()
        .installer_fetch_protocol = Some(crate::host::installer_bootstrap::PROTOCOL.into());
    let root = tempfile::tempdir().unwrap();
    let directory = root.path();
    let instance = "i-0123456789abcdef0";
    let installer = "opaque installer bytes";
    foundation::write_private(
        &directory.join("lightwallet-install.sh"),
        installer.as_bytes(),
    )
    .unwrap();
    let object = installer_object(
        &deployment,
        "lightwallet",
        &devnet::sha256(installer.as_bytes()),
        installer.len(),
    )
    .unwrap();
    let script = selected_fetch_installer(&deployment, &object, INSTALL_TIMEOUT).unwrap();
    assert!(!script.contains("python"));
    let request = json!({"DocumentName":"AWS-RunShellScript","DocumentVersion":"1","InstanceIds":[instance],
        "TimeoutSeconds":120,"MaxConcurrency":"1","MaxErrors":"0","CloudWatchOutputConfig":{"CloudWatchOutputEnabled":false},
        "Parameters":{"commands":[script],"executionTimeout":[INSTALL_TIMEOUT.to_string()],"workingDirectory":["/"]}});
    let id = Uuid::new_v4();
    let mut journal = json!({"apiVersion":crate::ssm::API_VERSION,"requestSha256":devnet::sha256(&serde_json::to_vec(&request).unwrap()),
        "instanceId":instance,"timeoutSecs":INSTALL_TIMEOUT,"attempts":[{"id":id,"createdAt":1,"comment":format!("zdn-command-{id}"),
        "commandId":Uuid::new_v4().to_string(),"state":"succeeded","uncertain":false,"cancellationRequested":false,"failure":null,"output":{}}]});
    let path = directory.join("lightwallet-install-command.json");
    foundation::write_json(&path, &journal).unwrap();
    validate_installer(
        &deployment,
        directory,
        "lightwallet",
        instance,
        installer,
        INSTALL_TIMEOUT,
    )
    .unwrap();
    assert!(validate_installer(
        &deployment,
        directory,
        "lightwallet",
        instance,
        "different opaque bytes",
        INSTALL_TIMEOUT
    )
    .is_err());
    journal["requestSha256"] = json!("0".repeat(64));
    foundation::write_json(&path, &journal).unwrap();
    assert!(validate_installer(
        &deployment,
        directory,
        "lightwallet",
        instance,
        installer,
        INSTALL_TIMEOUT
    )
    .is_err());
    for unsupported in [None, Some("foreign-fetch/v1".into())] {
        deployment
            .cluster
            .as_mut()
            .unwrap()
            .installer_fetch_protocol = unsupported;
        assert!(selected_fetch_installer(&deployment, &object, INSTALL_TIMEOUT).is_err());
        assert!(validate_installer(
            &deployment,
            directory,
            "lightwallet",
            instance,
            installer,
            INSTALL_TIMEOUT
        )
        .is_err());
    }
}
