use std::{cell::RefCell, collections::BTreeMap, fs};

use serde_json::{json, Value};
use uuid::Uuid;
use zdn::{
    aws::{AwsApi, AwsSelection},
    endpoints::{session_document_resources, EndpointFile, Service, MAX_FILE_BYTES},
    foundation::Deployment,
};

fn file(lightwallet: bool, count: u8) -> EndpointFile {
    let mut value = json!({
        "apiVersion":"zdn-endpoints/v1alpha1",
        "networkId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
        "scope":{"team_id":"private-team","account_id":"123456789012","region":"us-east-1"},
        "bootstrapId":"965f7c13-e186-4d52-b7e3-ef92db98a0ec",
        "consensusFingerprint":"ab".repeat(32),"nodeCount":count,
        "targets":[{"service":"node-rpc","nodeId":"node-1","instanceId":"i-00000000000000001"}]
    });
    if lightwallet {
        value["targets"].as_array_mut().unwrap().push(json!({
            "service":"lightwallet-grpc","nodeId":if count == 1 {"node-1"} else {"node-2"},
            "instanceId":if count == 1 {"i-00000000000000001"} else {"i-00000000000000002"}
        }));
    }
    EndpointFile::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn admin() -> AwsSelection {
    AwsSelection {
        profile: "administrator".into(),
        account_id: "123456789012".into(),
        region: "us-east-1".into(),
    }
}

fn principals() -> Vec<String> {
    vec!["arn:aws:iam::123456789012:user/developer".into()]
}

#[test]
fn endpoint_roundtrip_contains_only_portable_non_secret_identity() {
    for count in 1..=3 {
        for lightwallet in [false, true] {
            let f = file(lightwallet, count);
            let bytes = serde_json::to_vec(&f).unwrap();
            assert_eq!(EndpointFile::from_json(&bytes).unwrap(), f);
            let text = String::from_utf8(bytes).unwrap();
            for forbidden in [
                "password",
                "cookie",
                "token",
                "secret",
                "profile",
                "s3://",
                "kms",
                "18232",
                "port",
                "documentName",
                "hostname",
            ] {
                assert!(!text.contains(forbidden), "{forbidden}");
            }
            assert_eq!(f.target(Service::LightwalletGrpc).is_some(), lightwallet);
        }
    }
}

#[test]
fn strict_schema_rejects_commands_credentials_hosts_ports_and_unknown_fields() {
    let valid = serde_json::to_value(file(true, 3)).unwrap();
    for (pointer, key, value) in [
        ("", "awsProfile", json!("admin")),
        ("", "credentials", json!({"accessKey":"secret"})),
        ("/scope", "backend", json!("s3://private/state")),
        ("/targets/0", "host", json!("169.254.169.254")),
        ("/targets/0", "remotePort", json!(22)),
        ("/targets/0", "localPort", json!(12345)),
        ("/targets/0", "documentName", json!("AWS-RunShellScript")),
    ] {
        let mut changed = valid.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(key.into(), value);
        assert!(
            EndpointFile::from_json(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "{key}"
        );
    }
    let duplicate = String::from_utf8(serde_json::to_vec(&valid).unwrap())
        .unwrap()
        .replacen("{", "{\"apiVersion\":\"zdn-endpoints/v1alpha1\",", 1);
    assert!(EndpointFile::from_json(duplicate.as_bytes()).is_err());
}

#[test]
fn malformed_cross_service_and_injected_identity_inputs_are_rejected() {
    let valid = serde_json::to_value(file(true, 3)).unwrap();
    for (pointer, value) in [
        ("/apiVersion", json!("future")),
        ("/networkId", json!(Uuid::nil())),
        ("/bootstrapId", json!(Uuid::nil())),
        ("/scope/account_id", json!("123456789012:*")),
        ("/scope/team_id", json!("${evil}")),
        ("/scope/region", json!("us-east-1 --endpoint-url evil")),
        ("/scope/region", json!("cn-north-1")),
        ("/consensusFingerprint", json!("AB".repeat(32))),
        ("/consensusFingerprint", json!("a")),
        ("/nodeCount", json!(0)),
        ("/nodeCount", json!(4)),
        ("/targets", json!([])),
        ("/targets/0/service", json!("shell")),
        ("/targets/0/nodeId", json!("node-2")),
        (
            "/targets/0/instanceId",
            json!("i-00000000000000001 --command whoami"),
        ),
        ("/targets/1/instanceId", json!("i-00000000000000001")),
        ("/targets/1/service", json!("node-rpc")),
        ("/targets/1/nodeId", json!("node-3")),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            EndpointFile::from_json(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn identity_binding_checks_network_team_account_region_bootstrap_and_chain() {
    let f = file(true, 3);
    f.validate_identity(
        &f.scope,
        f.bootstrap_id,
        f.network_id,
        &f.consensus_fingerprint,
    )
    .unwrap();
    for mode in 0..6 {
        let mut other = f.clone();
        match mode {
            0 => other.scope.team_id = "other-team".into(),
            1 => other.scope.account_id = "999999999999".into(),
            2 => other.scope.region = "us-east-2".into(),
            3 => other.network_id = Uuid::new_v4(),
            4 => other.bootstrap_id = Uuid::new_v4(),
            _ => other.consensus_fingerprint = "ff".repeat(32),
        }
        assert!(
            other
                .validate_identity(
                    &f.scope,
                    f.bootstrap_id,
                    f.network_id,
                    &f.consensus_fingerprint
                )
                .is_err(),
            "{mode}"
        );
    }
}

#[test]
fn endpoint_file_loading_is_bounded_and_publication_never_clobbers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("endpoints.json");
    let f = file(true, 3);
    f.save_new(&path).unwrap();
    assert_eq!(EndpointFile::load(&path).unwrap(), f);
    assert!(f.save_new(&path).is_err());
    assert_eq!(EndpointFile::load(&path).unwrap(), f);
    fs::write(&path, vec![b' '; MAX_FILE_BYTES + 1]).unwrap();
    assert!(EndpointFile::load(&path).is_err());
    assert!(EndpointFile::from_json(&vec![b' '; MAX_FILE_BYTES + 1]).is_err());
    assert!(EndpointFile::load(dir.path()).is_err());
    #[cfg(unix)]
    {
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(EndpointFile::load(&link).is_err());
    }
}

#[test]
fn fixed_session_documents_expose_only_a_local_port_parameter() {
    let f = file(true, 3);
    for lightwallet in [false, true] {
        let resources =
            session_document_resources(&f.scope, f.bootstrap_id, f.network_id, lightwallet)
                .unwrap();
        assert_eq!(resources.len(), if lightwallet { 2 } else { 1 });
        for service in [Service::NodeRpc, Service::LightwalletGrpc] {
            if service == Service::LightwalletGrpc && !lightwallet {
                continue;
            }
            let resource = &resources[service.document_key()];
            assert_eq!(resource["type"], "aws:ssm:Document");
            assert_eq!(resource["properties"]["name"], f.document_name(service));
            assert_eq!(resource["properties"]["documentType"], "Session");
            let document: Value =
                serde_json::from_str(resource["properties"]["content"].as_str().unwrap()).unwrap();
            assert_eq!(document["sessionType"], "Port");
            assert_eq!(
                document["parameters"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .collect::<Vec<_>>(),
                ["localPortNumber"]
            );
            assert_eq!(
                document["properties"]["portNumber"],
                service.remote_port().to_string()
            );
            assert_eq!(
                document["properties"]["localPortNumber"],
                "{{ localPortNumber }}"
            );
            assert!(document["properties"].get("host").is_none());
            assert!(!document.to_string().contains("18232"));
        }
    }
}

#[test]
fn document_namespace_binds_bootstrap_and_network_without_changing_file_schema() {
    let file = file(true, 3);
    for service in [Service::NodeRpc, Service::LightwalletGrpc] {
        let name = file.document_name(service);
        assert_eq!(
            name,
            format!(
                "zdn-{}-{}-{}-v1",
                file.bootstrap_id,
                file.network_id,
                service.name()
            )
        );
        assert!(name.len() < 128);
        let mut other_bootstrap = file.clone();
        other_bootstrap.bootstrap_id = Uuid::new_v4();
        assert_ne!(name, other_bootstrap.document_name(service));
        let mut other_network = file.clone();
        other_network.network_id = Uuid::new_v4();
        assert_ne!(name, other_network.document_name(service));
        let policy = file.participant_policy().unwrap();
        assert!(!permits(
            &policy,
            "ssm:StartSession",
            &other_bootstrap.document_arn(service),
            &json!({})
        ));
        assert!(!permits(
            &policy,
            "ssm:StartSession",
            &other_network.document_arn(service),
            &json!({})
        ));
    }
}

// Deliberately limited fixture evaluator. IAM service/resource policy behavior
// still requires the live qualification; this independently checks emitted intent.
fn permits(policy: &Value, action: &str, resource: &str, context: &Value) -> bool {
    fn strings(value: &Value) -> Vec<&str> {
        if let Some(s) = value.as_str() {
            vec![s]
        } else {
            value
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect()
        }
    }
    fn matches(pattern: &str, value: &str) -> bool {
        pattern
            .strip_suffix('*')
            .map_or(pattern == value, |p| value.starts_with(p))
    }
    policy["Statement"]
        .as_array()
        .unwrap()
        .iter()
        .any(|statement| {
            assert_eq!(statement["Effect"], "Allow");
            strings(&statement["Action"]).contains(&action)
                && strings(&statement["Resource"])
                    .iter()
                    .any(|p| matches(p, resource))
                && statement.get("Condition").is_none_or(|condition| {
                    condition
                        .as_object()
                        .unwrap()
                        .iter()
                        .all(|(operator, terms)| {
                            assert!(["BoolIfExists", "StringEquals"].contains(&operator.as_str()));
                            terms.as_object().unwrap().iter().all(|(key, expected)| {
                                context
                                    .get(key)
                                    .map_or(operator == "BoolIfExists", |actual| {
                                        strings(actual)
                                            .iter()
                                            .any(|v| strings(expected).contains(v))
                                    })
                            })
                        })
                })
        })
}

#[test]
fn participant_policy_denies_state_shell_other_networks_and_missing_ownership() {
    let f = file(true, 3);
    let policy = f.participant_policy().unwrap();
    let context = json!({
        "ssm:resourceTag/zdn:managed-by":"zdn",
        "ssm:resourceTag/zdn:team-id":f.scope.team_id,
        "ssm:resourceTag/zdn:bootstrap":f.bootstrap_id.to_string(),
        "ssm:resourceTag/zdn:network-id":f.network_id.to_string()
    });
    for target in &f.targets {
        assert!(permits(
            &policy,
            "ssm:StartSession",
            &f.instance_arn(target),
            &context
        ));
        assert!(permits(
            &policy,
            "ssm:StartSession",
            &f.document_arn(target.service),
            &json!({})
        ));
        assert!(permits(
            &policy,
            "ssm:GetDocument",
            &f.document_arn(target.service),
            &json!({})
        ));
    }
    for key in context.as_object().unwrap().keys() {
        let mut missing = context.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            !permits(
                &policy,
                "ssm:StartSession",
                &f.instance_arn(&f.targets[0]),
                &missing
            ),
            "{key}"
        );
        missing[key] = json!("different");
        assert!(
            !permits(
                &policy,
                "ssm:StartSession",
                &f.instance_arn(&f.targets[0]),
                &missing
            ),
            "{key}"
        );
    }
    for (action, resource) in [
        (
            "ssm:StartSession",
            "arn:aws:ec2:us-east-1:123456789012:instance/i-00000000000000003",
        ),
        (
            "ssm:StartSession",
            "arn:aws:ssm:us-east-1::document/AWS-StartPortForwardingSession",
        ),
        (
            "ssm:StartSession",
            "arn:aws:ssm:us-east-1:123456789012:document/SSM-SessionManagerRunShell",
        ),
        (
            "ssm:SendCommand",
            "arn:aws:ec2:us-east-1:123456789012:instance/i-00000000000000001",
        ),
        (
            "ssm:UpdateDocument",
            "arn:aws:ssm:us-east-1:123456789012:document/allowed",
        ),
        ("s3:GetObject", "arn:aws:s3:::zdn-private-team/state"),
        ("s3:PutObject", "arn:aws:s3:::zdn-private-team/state"),
        ("kms:Decrypt", "arn:aws:kms:us-east-1:123456789012:key/test"),
        ("iam:PassRole", &f.participant_role_arn()),
        ("ec2:DescribeInstances", "*"),
        (
            "ec2:TerminateInstances",
            "arn:aws:ec2:us-east-1:123456789012:instance/i-00000000000000001",
        ),
    ] {
        assert!(
            !permits(&policy, action, resource, &context),
            "{action} {resource}"
        );
    }
    let disabled = file(false, 3);
    assert!(!permits(
        &disabled.participant_policy().unwrap(),
        "ssm:StartSession",
        &disabled.document_arn(Service::LightwalletGrpc),
        &json!({})
    ));
}

#[test]
fn instance_authorization_allows_absent_document_check_but_rejects_false() {
    let f = file(true, 3);
    let policy = f.participant_policy().unwrap();
    let statement = policy["Statement"]
        .as_array()
        .unwrap()
        .iter()
        .find(|statement| statement["Sid"] == "StartOnlyNetworkInstances")
        .unwrap();
    let ownership = json!({
        "ssm:resourceTag/zdn:managed-by":"zdn",
        "ssm:resourceTag/zdn:team-id":f.scope.team_id,
        "ssm:resourceTag/zdn:bootstrap":f.bootstrap_id.to_string(),
        "ssm:resourceTag/zdn:network-id":f.network_id.to_string()
    });
    assert_eq!(
        statement["Condition"],
        json!({
            "BoolIfExists":{"ssm:SessionDocumentAccessCheck":"true"},
            "StringEquals":ownership
        })
    );
    // IAM evaluates all resource authorizations for StartSession. The EC2
    // target can omit the document-specific key; false must still fail, and
    // the separate exact document resource authorization is still required.
    for (value, accepted) in [(None, true), (Some("true"), true), (Some("false"), false)] {
        let mut context = ownership.clone();
        if let Some(value) = value {
            context["ssm:SessionDocumentAccessCheck"] = json!(value);
        }
        for target in &f.targets {
            assert_eq!(
                permits(
                    &policy,
                    "ssm:StartSession",
                    &f.instance_arn(target),
                    &context
                ),
                accepted,
                "document check: {value:?}"
            );
        }
    }
}

#[test]
fn termination_requires_current_caller_system_tag_and_network_target() {
    let policy = file(true, 3).participant_policy().unwrap();
    let resource = "arn:aws:ssm:us-east-1:123456789012:session/caller-random";
    let context = json!({
        "ssm:resourceTag/aws:ssmmessages:target-id":"i-00000000000000001",
        "ssm:resourceTag/aws:ssmmessages:session-id":"${aws:userid}"
    });
    assert!(permits(&policy, "ssm:TerminateSession", resource, &context));
    for key in context.as_object().unwrap().keys() {
        let mut other = context.clone();
        other[key] = json!("different");
        assert!(!permits(&policy, "ssm:TerminateSession", resource, &other));
    }
    assert!(!permits(
        &policy,
        "ssm:TerminateSession",
        "arn:aws:ssm:us-east-2:123456789012:session/caller-random",
        &context
    ));
    assert!(!permits(&policy, "ssm:ResumeSession", resource, &context));
}

#[test]
fn participant_role_renderer_is_scoped_protected_and_escapes_iam_variables() {
    let f = file(true, 3);
    let program = f.render_participant(&admin(), &principals()).unwrap();
    let resources = program["resources"].as_object().unwrap();
    assert_eq!(resources.len(), 3);
    let role = &resources["participantRole"];
    assert_eq!(
        role["properties"]["path"],
        "/zdn-participants/965f7c13-e186-4d52-b7e3-ef92db98a0ec/"
    );
    assert_eq!(role["properties"]["name"], f.participant_role_name());
    assert_eq!(
        role["properties"]["tags"]["zdn:network-id"],
        f.network_id.to_string()
    );
    assert_eq!(role["options"]["protect"], true);
    assert_eq!(resources["participantPolicy"]["options"]["protect"], true);
    let policy = resources["participantPolicy"]["properties"]["policy"]
        .as_str()
        .unwrap();
    assert!(policy.contains("$${aws:userid}"));
    assert_eq!(
        serde_json::from_str::<Value>(&policy.replace("$${", "${")).unwrap(),
        f.participant_policy().unwrap()
    );
    assert!(!program.to_string().contains("s3://"));
    let mut wrong = admin();
    wrong.account_id = "999999999999".into();
    assert!(f.render_participant(&wrong, &principals()).is_err());
}

#[test]
fn distinct_trusted_principals_cannot_select_each_others_session_identity() {
    let f = file(true, 3);
    let principals: Vec<String> = [
        "arn:aws:iam::123456789012:user/alice",
        "arn:aws:iam::123456789012:user/bob",
        "arn:aws:iam::123456789012:role/ci",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let names = f.participant_session_names(&principals).unwrap();
    let trust = f.participant_trust_policy(&principals).unwrap();
    let assume = |caller: &str, requested: Option<&str>| {
        trust["Statement"].as_array().unwrap().iter().any(|s| {
            s["Effect"] == "Allow"
                && s["Action"] == "sts:AssumeRole"
                && s["Principal"]["AWS"] == caller
                && requested.is_some_and(|name| {
                    s["Condition"]["StringEquals"]["sts:RoleSessionName"] == name
                })
        })
    };
    for (owner, name) in &names {
        assert!((2..=64).contains(&name.len()));
        assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        assert!(!assume(owner, None));
        assert!(!assume(owner, Some("arbitrary")));
        assert!(!assume(
            "arn:aws:iam::123456789012:user/outsider",
            Some(name)
        ));
        for (caller, caller_name) in &names {
            assert_eq!(assume(caller, Some(name)), caller == owner);
            // Model IAM's variable expansion using distinct STS user IDs,
            // rather than putting the literal ${aws:userid} in both sides.
            let policy: Value = serde_json::from_str(
                &f.participant_policy()
                    .unwrap()
                    .to_string()
                    .replace("${aws:userid}", &format!("AROAEXAMPLE:{caller_name}")),
            )
            .unwrap();
            let context = json!({
                "ssm:resourceTag/aws:ssmmessages:target-id":f.targets[0].instance_id,
                "ssm:resourceTag/aws:ssmmessages:session-id":format!("AROAEXAMPLE:{name}")
            });
            assert_eq!(
                permits(
                    &policy,
                    "ssm:TerminateSession",
                    "arn:aws:ssm:us-east-1:123456789012:session/known-session",
                    &context
                ),
                caller == owner
            );
        }
    }
    let mut reversed = principals.clone();
    reversed.reverse();
    assert_eq!(trust, f.participant_trust_policy(&reversed).unwrap());
    // Adding another participant must not change an existing profile's name.
    assert_eq!(
        names[&principals[0]],
        f.participant_session_names(&principals[..1]).unwrap()[&principals[0]]
    );
}

#[test]
fn oversized_principal_conditions_fail_before_rendering_cloud_resources() {
    let principals = (0..20)
        .map(|i| format!("arn:aws:iam::123456789012:user/developer-{i}"))
        .collect::<Vec<_>>();
    let error = file(false, 1)
        .render_participant(&admin(), &principals)
        .unwrap_err();
    assert!(error.to_string().contains("2048-character IAM limit"));
}

#[test]
fn trust_rejects_wildcards_roots_sessions_cross_accounts_and_zdn_roles() {
    let f = file(true, 3);
    f.participant_trust_policy(&principals()).unwrap();
    for principal in [
        "*".to_owned(),
        "arn:aws:iam::123456789012:root".into(),
        "arn:aws:iam::999999999999:user/developer".into(),
        "arn:aws:sts::123456789012:assumed-role/Developer/session".into(),
        "arn:aws:iam::123456789012:role/Developer*".into(),
        "arn:aws:iam::123456789012:role/zdn/host-role".into(),
        "arn:aws:iam::123456789012:role/zdn-admin/deployment".into(),
        f.participant_role_arn(),
    ] {
        assert!(
            f.participant_trust_policy(std::slice::from_ref(&principal))
                .is_err(),
            "{principal}"
        );
    }
    assert!(f.participant_trust_policy(&[]).is_err());
    assert!(f
        .participant_trust_policy(&[principals()[0].clone(), principals()[0].clone()])
        .is_err());
}

struct Documents {
    file: EndpointFile,
    mutate: Option<(&'static str, Value)>,
    calls: RefCell<Vec<Value>>,
}
impl AwsApi for Documents {
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra: &[String],
    ) -> eyre::Result<Value> {
        assert_eq!((service, operation), ("ssm", "get-document"));
        assert!(extra.is_empty());
        let target = self
            .file
            .targets
            .iter()
            .find(|target| input["Name"] == self.file.document_arn(target.service))
            .unwrap();
        assert_eq!(input["DocumentVersion"], "$DEFAULT");
        self.calls.borrow_mut().push(input);
        let mut response = json!({"Name":self.file.document_arn(target.service),"DocumentType":"Session","DocumentFormat":"JSON","Status":"Active","Content":target.service.session_document().to_string()});
        if let Some((key, value)) = &self.mutate {
            response[*key] = value.clone();
        }
        Ok(response)
    }
}

#[test]
fn live_document_verification_uses_only_exact_reads_and_rejects_drift() {
    let f = file(true, 3);
    let api = Documents {
        file: f.clone(),
        mutate: None,
        calls: RefCell::default(),
    };
    f.validate_live_documents(&api).unwrap();
    assert_eq!(api.calls.borrow().len(), 2);
    for (key, value) in [
        ("Name", json!("AWS-StartPortForwardingSession")),
        ("DocumentType", json!("Command")),
        ("DocumentFormat", json!("YAML")),
        ("Status", json!("Updating")),
        ("Content", json!("{}")),
        ("Content", json!("x".repeat(MAX_FILE_BYTES + 1))),
    ] {
        let api = Documents {
            file: f.clone(),
            mutate: Some((key, value)),
            calls: RefCell::default(),
        };
        assert!(f.validate_live_documents(&api).is_err(), "{key}");
        assert_eq!(api.calls.borrow().len(), 1);
    }
}

#[test]
fn live_document_identity_accepts_only_exact_arn_or_canonical_basename() {
    let f = file(false, 1);
    let arn = f.document_arn(Service::NodeRpc);
    let name = f.document_name(Service::NodeRpc);
    for (returned_name, accepted) in [
        (arn.clone(), true),
        (name.clone(), true),
        (arn.replace(&f.scope.account_id, "999999999999"), false),
        (arn.replace(&f.scope.region, "us-west-2"), false),
        (arn.replace(&name, "other-document"), false),
        (format!("{arn}/"), false),
        (format!(" {name}"), false),
    ] {
        let api = Documents {
            file: f.clone(),
            mutate: Some(("Name", json!(returned_name))),
            calls: RefCell::default(),
        };
        assert_eq!(
            f.validate_live_documents(&api).is_ok(),
            accepted,
            "returned document identity: {returned_name}"
        );
        assert_eq!(api.calls.borrow().len(), 1);
    }
}

fn deployment() -> Deployment {
    let f = file(false, 1);
    let mut manifest: Value =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    manifest["checkpoints"] = json!([{"height":0,"hash":manifest["genesis"]["hash"]}]);
    let artifacts: BTreeMap<_, _> = [
        "manifest.json",
        "chain.tar",
        "image.json",
        "image-manifest.json",
        "image-config.json",
        "zdn",
    ]
    .into_iter()
    .map(|name| (name, json!({"sha256":"a".repeat(64),"bytes":1})))
    .collect();
    let mut team: zdn::aws::TeamDefinition = serde_json::from_value(json!({
        "apiVersion":"zdn-team/v1alpha1","teamId":"private-team","revision":1,"bootstrapId":f.bootstrap_id,
        "aws":{"accountId":"123456789012","region":"us-east-1"},
        "state":{"backend":"s3://zdn-private-team/pulumi/zdn","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"}
    })).unwrap();
    team.deployment = Some(zdn::access::DeploymentAccess::managed(&team));
    team.api_version = zdn::access::TEAM_ROLE_API_VERSION.into();
    let request = json!({
        "apiVersion":"zdn-private-nodes/v1alpha1","configSha256":"a".repeat(64),"manifest":manifest,
        "clientAccess":true,
        "image":{"apiVersion":zdn::image::API_VERSION,"image":format!("123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/node@sha256:{}","b".repeat(64)),
            "configDigest":format!("sha256:{}","c".repeat(64)),"platform":"linux/amd64",
            "provenance":{"kind":"release","revision":"d".repeat(40),"version":"v0.0.1"},
            "capabilities":zdn::image::ImageCapabilities::default(),"binaryPath":zdn::image::NODE_BINARY,"environmentLauncher":zdn::image::ENV_ENTRYPOINT},
        "nodeCount":1,"rewardAddress":"t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB","artifacts":artifacts
    });
    let value = json!({
        "schema_version":1,"cluster":request,"team":team,"owner_id":Uuid::new_v4(),"stack_initialized":true,
        "last_operation":Uuid::new_v4(),"destroyed":false,"cleanup":null,
        "spec":{"scope":f.scope,"network_id":f.network_id,"aws_profile":"developer","ami_id":"ami-0123456789abcdef0","availability_zone":"us-east-1a","size":"medium","retain_chain_disk":true},
        "outputs":{"schema_version":1,"scope":f.scope,"network_id":f.network_id,"availability_zone":"us-east-1a",
            "vpc_id":"vpc-00000000000000001","private_subnet_id":"subnet-00000000000000001","instance_id":"i-00000000000000001","private_ip":"10.90.1.10",
            "chain_volume_id":"vol-00000000000000001","retain_chain_disk":true,"security_group_id":"sg-00000000000000001","nat_gateway_id":"nat-00000000000000001","eip_allocation_id":"eipalloc-00000000000000001",
            "nodes":{"node-1":{"node_id":"node-1","instance_id":"i-00000000000000001","private_ip":"10.90.1.10","volume_id":"vol-00000000000000001"}}}
    });
    serde_json::from_value(value).unwrap()
}

#[test]
fn export_requires_valid_cluster_outputs_and_current_client_access_receipt() {
    let d = deployment();
    d.validate().unwrap();
    let endpoints = EndpointFile::from_deployment(&d).unwrap();
    endpoints.validate_for(&d).unwrap();
    for mode in 0..7 {
        let mut changed = d.clone();
        match mode {
            0 => changed.destroyed = true,
            1 => changed.unresolved_operation = Some(Uuid::new_v4()),
            2 => changed.outputs = None,
            3 => changed.cluster = None,
            4 => changed.cluster.as_mut().unwrap().client_access = false,
            5 => changed.outputs.as_mut().unwrap().scope.team_id = "foreign".into(),
            _ => {
                changed
                    .outputs
                    .as_mut()
                    .unwrap()
                    .nodes
                    .get_mut("node-1")
                    .unwrap()
                    .instance_id = "invalid".into()
            }
        }
        assert!(EndpointFile::from_deployment(&changed).is_err(), "{mode}");
    }
    let mut changed = endpoints.clone();
    changed.targets[0].instance_id = "i-00000000000000002".into();
    assert!(changed.validate_for(&d).is_err());
    let mut pending = d.clone();
    pending.cluster.as_mut().unwrap().block_interval_seconds = Some(25);
    zdn::foundation::update_controller::prepare(&mut pending, &["node-1".into()], true).unwrap();
    assert!(EndpointFile::from_deployment(&pending)
        .unwrap_err()
        .to_string()
        .contains("image update"));
}
