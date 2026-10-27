#[path = "support/iam.rs"]
mod iam;

use iam::{permitted, strings};
use serde_json::{json, Value};
use zdn::{access::*, aws::*, build_infra::BuildInfrastructure};

fn team() -> TeamDefinition {
    serde_json::from_value(json!({
        "apiVersion":"zdn-team/v1alpha1","teamId":"test-team","revision":1,
        "bootstrapId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
        "aws":{"accountId":"123456789012","region":"us-east-1"},
        "state":{"backend":"s3://zdn-test-state/pulumi/zdn","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"}
    })).unwrap()
}

#[test]
fn names_validate_and_isolate_all_ownership_dimensions() {
    let team = team();
    let infra = BuildInfrastructure::for_team(&team).unwrap();
    assert_eq!(infra, BuildInfrastructure::for_team(&team).unwrap());
    assert_eq!(
        infra.repository_uri,
        format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/{}",
            infra.repository
        )
    );
    for field in ["team", "bootstrap", "account", "region"] {
        let mut other = team.clone();
        match field {
            "team" => other.team_id = "other".into(),
            "bootstrap" => other.bootstrap_id = uuid::Uuid::new_v4(),
            "account" => {
                other.aws.account_id = "999999999999".into();
                other.state.kms_key_arn = other
                    .state
                    .kms_key_arn
                    .replace("123456789012", "999999999999");
            }
            _ => {
                other.aws.region = "us-west-2".into();
                other.state.kms_key_arn = other.state.kms_key_arn.replace("us-east-1", "us-west-2");
            }
        }
        let changed = BuildInfrastructure::for_team(&other).unwrap();
        assert_ne!(infra.source_bucket, changed.source_bucket);
        assert_ne!(infra.project_name, changed.project_name);
        assert_ne!(infra.repository, changed.repository);
        assert!(infra.resources(&other).is_err());
    }
    let mut invalid = team.clone();
    invalid.revision = 0;
    assert!(BuildInfrastructure::for_team(&invalid).is_err());
}

#[test]
fn administrator_resources_are_private_protected_and_native() {
    let team = team();
    let infra = BuildInfrastructure::for_team(&team).unwrap();
    let resources = infra.resources(&team).unwrap();
    for resource in resources.values() {
        assert_eq!(resource["options"]["provider"], "${provider}");
        assert_eq!(resource["options"]["protect"], true);
    }
    let props = |name: &str| &resources[name]["properties"];
    assert_eq!(props("buildBucket")["forceDestroy"], false);
    assert_eq!(props("buildBucket")["bucket"], infra.source_bucket);
    for flag in [
        "blockPublicAcls",
        "blockPublicPolicy",
        "ignorePublicAcls",
        "restrictPublicBuckets",
    ] {
        assert_eq!(props("buildBucketPublicAccess")[flag], true);
    }
    assert_eq!(
        props("buildBucketOwnership")["rule"]["objectOwnership"],
        "BucketOwnerEnforced"
    );
    assert_eq!(
        props("buildBucketVersioning")["versioningConfiguration"]["status"],
        "Enabled"
    );
    assert_eq!(
        props("buildBucketEncryption")["rules"][0]["applyServerSideEncryptionByDefault"]
            ["sseAlgorithm"],
        "AES256"
    );
    let bucket_policy: Value =
        serde_json::from_str(props("buildBucketPolicy")["policy"].as_str().unwrap()).unwrap();
    assert_eq!(
        bucket_policy["Statement"][0],
        json!({"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":[format!("arn:aws:s3:::{}",infra.source_bucket),format!("arn:aws:s3:::{}/*",infra.source_bucket)],"Condition":{"Bool":{"aws:SecureTransport":"false"}}})
    );
    assert_eq!(
        bucket_policy["Statement"][1],
        json!({"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":format!("arn:aws:s3:::{}/cache/*",infra.source_bucket),"Condition":{"Null":{"s3:x-amz-server-side-encryption":"false"},"StringNotEquals":{"s3:x-amz-server-side-encryption":["AES256","aws:kms"]}}})
    );
    assert_eq!(props("buildRepository")["imageTagMutability"], "IMMUTABLE");
    assert_eq!(
        props("buildRepository")["imageScanningConfiguration"]["scanOnPush"],
        true
    );
    assert_eq!(
        props("buildRepository")["encryptionConfigurations"][0]["encryptionType"],
        "AES256"
    );
    assert_eq!(props("buildRepository")["forceDelete"], false);
    let project = props("buildProject");
    assert_eq!(
        project["environment"],
        json!({"type":"LINUX_CONTAINER","computeType":"BUILD_GENERAL1_MEDIUM","image":"aws/codebuild/standard:7.0","privilegedMode":true,"imagePullCredentialsType":"CODEBUILD"})
    );
    assert_eq!(project["source"]["type"], "NO_SOURCE");
    assert!(project["source"]["buildspec"]
        .as_str()
        .unwrap()
        .contains("'false'"));
    assert_eq!(project["artifacts"]["type"], "NO_ARTIFACTS");
    assert_eq!(
        project["cache"],
        json!({"type":"S3","location":format!("{}/cache",infra.source_bucket),"cacheNamespace":infra.project_name})
    );
    assert!(project["buildTimeout"].as_u64().unwrap() <= 120);
    assert_eq!(project["serviceRole"], "${buildRole.arn}");
    let trust: Value =
        serde_json::from_str(props("buildRole")["assumeRolePolicy"].as_str().unwrap()).unwrap();
    assert_eq!(
        trust["Statement"][0]["Principal"],
        json!({"Service":"codebuild.amazonaws.com"})
    );
    assert_eq!(
        trust["Statement"][0]["Condition"],
        json!({"StringEquals":{"aws:SourceAccount":infra.account_id},"ArnEquals":{"aws:SourceArn":format!("arn:aws:codebuild:us-east-1:123456789012:project/{}",infra.project_name)}})
    );
}

#[test]
fn exact_build_permissions_exclude_state_admin_and_executor_mutation() {
    let team = team();
    let infra = BuildInfrastructure::for_team(&team).unwrap();
    let resources = infra.resources(&team).unwrap();
    let service: Value = serde_json::from_str(
        resources["buildServicePolicy"]["properties"]["policy"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let deployment = infra.deployment_policy();
    let source = format!("arn:aws:s3:::{}/sources/hash.tar", infra.source_bucket);
    let result = format!(
        "arn:aws:s3:::{}/results/attempt/image.json",
        infra.source_bucket
    );
    let cache = format!("arn:aws:s3:::{}/cache/namespace/key", infra.source_bucket);
    let index = format!(
        "arn:aws:s3:::{}/images/fingerprint.json",
        infra.source_bucket
    );
    let repo = format!(
        "arn:aws:ecr:us-east-1:123456789012:repository/{}",
        infra.repository
    );
    let project = format!(
        "arn:aws:codebuild:us-east-1:123456789012:project/{}",
        infra.project_name
    );
    let context =
        json!({"aws:RequestedRegion":"us-east-1","s3:x-amz-server-side-encryption":"AES256"});
    let allowed = |doc: &Value, action: &str, arn: &str| {
        permitted(std::slice::from_ref(doc), action, arn, &context)
    };
    for (action, arn) in [
        ("s3:GetObjectVersion", &source),
        ("s3:PutObject", &result),
        ("s3:GetObject", &cache),
        ("s3:PutObject", &cache),
        ("ecr:PutImage", &repo),
        ("ecr:BatchGetImage", &repo),
    ] {
        assert!(allowed(&service, action, arn));
    }
    let bucket = format!("arn:aws:s3:::{}", infra.source_bucket);
    for prefix in [
        "cache/",
        "cache/namespace/key",
        "sources/",
        "results/",
        "",
        "cache-other/",
    ] {
        assert_eq!(
            permitted(
                std::slice::from_ref(&service),
                "s3:ListBucket",
                &bucket,
                &json!({"s3:prefix":prefix})
            ),
            prefix.starts_with("cache/")
        );
    }
    for action in ["s3:GetBucketAcl", "s3:GetBucketLocation"] {
        assert!(allowed(&service, action, &bucket));
        assert!(!allowed(&deployment, action, &bucket));
    }
    // GetObject's missing-key check has no prefix context. Listing is allowed
    // only on this team's build bucket, not state or other teams' buckets.
    for (arn, expected) in [
        (bucket.clone(), true),
        (format!("{bucket}-other"), false),
        ("arn:aws:s3:::zdn-test-state".into(), false),
    ] {
        assert_eq!(
            permitted(
                std::slice::from_ref(&deployment),
                "s3:ListBucket",
                &arn,
                &json!({})
            ),
            expected
        );
    }
    for (action, arn) in [
        ("s3:PutObject", &source),
        ("s3:GetObject", &result),
        ("s3:GetObject", &index),
        ("s3:PutObject", &index),
        ("ecr:BatchGetImage", &repo),
        ("codebuild:StartBuild", &project),
        ("codebuild:StopBuild", &project),
        ("codebuild:BatchGetBuilds", &project),
        ("codebuild:BatchGetProjects", &project),
        ("codebuild:ListBuildsForProject", &project),
    ] {
        assert!(allowed(&deployment, action, arn));
    }
    // Inline commands are intentional; changing the native executor or role is not.
    assert!(permitted(
        std::slice::from_ref(&deployment),
        "codebuild:StartBuild",
        &project,
        &json!({"codebuild:source.buildspec":"inline"})
    ));
    for key in [
        "codebuild:environment",
        "codebuild:serviceRole",
        "codebuild:cache",
        "codebuild:artifacts",
        "codebuild:secondarySources",
        "codebuild:secondaryArtifacts",
        "codebuild:autoRetryLimit",
    ] {
        assert!(
            !permitted(
                std::slice::from_ref(&deployment),
                "codebuild:StartBuild",
                &project,
                &json!({key:"override"})
            ),
            "unexpected override permission: {key}"
        );
    }
    assert!(!permitted(
        std::slice::from_ref(&deployment),
        "s3:PutObject",
        &source,
        &json!({})
    ));
    for context in [
        json!({}),
        json!({"s3:x-amz-server-side-encryption":"aws:kms"}),
    ] {
        assert!(!permitted(
            std::slice::from_ref(&deployment),
            "s3:PutObject",
            &index,
            &context
        ));
    }
    let bucket_policy: Value = serde_json::from_str(
        resources["buildBucketPolicy"]["properties"]["policy"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    // Evaluate actual identity and resource policies together, including explicit
    // denies: CodeBuild's managed cache encryption is independent of the default.
    for encryption in [None, Some("AES256"), Some("aws:kms"), Some("unsupported")] {
        for secure in ["true", "false"] {
            let mut context = json!({"aws:SecureTransport":secure});
            if let Some(encryption) = encryption {
                context["s3:x-amz-server-side-encryption"] = json!(encryption);
            }
            assert_eq!(
                permitted(
                    &[service.clone(), bucket_policy.clone()],
                    "s3:PutObject",
                    &cache,
                    &context
                ),
                secure == "true" && encryption != Some("unsupported"),
                "cache upload: encryption={encryption:?}, secure={secure}"
            );
            for arn in [
                format!("arn:aws:s3:::{}/cache-other/key", infra.source_bucket),
                format!("arn:aws:s3:::{}-other/cache/key", infra.source_bucket),
            ] {
                assert!(!permitted(
                    &[service.clone(), bucket_policy.clone()],
                    "s3:PutObject",
                    &arn,
                    &context
                ));
            }
            for arn in [&source, &index] {
                assert_eq!(
                    permitted(
                        &[deployment.clone(), bucket_policy.clone()],
                        "s3:PutObject",
                        arn,
                        &context
                    ),
                    secure == "true" && encryption == Some("AES256"),
                    "source/index upload: {arn}, encryption={encryption:?}, secure={secure}"
                );
            }
        }
    }
    for (doc, action, arn) in [
        (&service, "s3:GetObject", &source),
        (&service, "s3:PutObject", &source),
        (&service, "s3:GetObject", &result),
        (&deployment, "s3:GetObjectVersion", &source),
        (&deployment, "s3:PutObject", &result),
        (&deployment, "ecr:PutImage", &repo),
        (&deployment, "codebuild:UpdateProject", &project),
        (&deployment, "s3:GetObject", &cache),
        (&deployment, "s3:PutObject", &cache),
        (&service, "s3:GetObject", &index),
        (&service, "s3:PutObject", &index),
        (&service, "s3:GetObjectVersion", &cache),
        (&service, "s3:DeleteObject", &cache),
        (&deployment, "s3:DeleteObject", &index),
        (
            &deployment,
            "codebuild:ListBuildsForProject",
            &format!("{project}-other"),
        ),
    ] {
        assert!(!allowed(doc, action, arn), "unexpected {action} {arn}");
    }
    for doc in [&service, &deployment] {
        for statement in doc["Statement"].as_array().unwrap() {
            for action in strings(&statement["Action"]) {
                assert!(!action.contains('*'));
                if action == "ecr:GetAuthorizationToken" {
                    // This API has no repository-level resource scope.
                    assert_eq!(statement["Resource"], "*");
                    continue;
                }
                if action.starts_with("s3:")
                    || (action.starts_with("ecr:") && action != "ecr:GetAuthorizationToken")
                {
                    assert!(strings(&statement["Resource"])
                        .iter()
                        .all(|r| *r != "*" && !r.contains("zdn-test-state")));
                }
                for foreign in [
                    "arn:aws:s3:::zdn-test-state/pulumi/zdn/file",
                    "arn:aws:s3:::zdn-test-state/zdn-admin/file",
                    "arn:aws:ecr:us-east-1:123456789012:repository/other",
                ] {
                    assert!(!allowed(doc, action, foreign));
                }
            }
        }
        assert!(!allowed(doc, "iam:PassRole", "*"));
        assert!(!allowed(
            doc,
            "codebuild:StartBuild",
            &format!("{project}-other")
        ));
    }
    let stream = format!(
        "arn:aws:logs:us-east-1:123456789012:log-group:/aws/codebuild/{}:log-stream:attempt",
        infra.project_name
    );
    assert!(allowed(&service, "logs:CreateLogStream", &stream));
    assert!(allowed(&service, "logs:PutLogEvents", &stream));
    assert!(!allowed(&service, "logs:CreateLogGroup", &stream));
    assert!(!allowed(
        &service,
        "logs:PutLogEvents",
        &stream.replace(&infra.project_name, "other")
    ));
    assert!(allowed(&service, "ecr:GetAuthorizationToken", "*"));
    assert!(!permitted(
        &[service],
        "ecr:GetAuthorizationToken",
        "*",
        &json!({"aws:RequestedRegion":"us-west-2"})
    ));
    let req = AccessRequest {
        team: team.clone(),
        administrator: AwsSelection {
            profile: "admin".into(),
            account_id: infra.account_id.clone(),
            region: infra.region.clone(),
        },
        trusted_principals: vec!["arn:aws:iam::123456789012:user/developer".into()],
        existing: None,
    };
    let rendered = req.render().unwrap();
    assert_eq!(
        rendered["resources"]["buildProject"],
        resources["buildProject"]
    );
    assert_eq!(
        deployment_policies(&team, &req.access()).unwrap()["build"],
        deployment
    );
    let mut external = req;
    external.existing = Some(DeploymentAccess {
        role_arn: "arn:aws:iam::123456789012:role/external".into(),
        management: RoleManagement::External,
        runtime_boundary_arn: "arn:aws:iam::123456789012:policy/external".into(),
    });
    external.validate().unwrap();
    assert!(external.render().is_err());
}

#[test]
fn layer_cache_render_reuses_sources_but_isolates_recipes_teams_and_attempts() {
    use zdn::{
        build::{BuildContract, BuildRecipe},
        build_job::{native_buildspec, NativeExporter},
    };
    let infra = BuildInfrastructure::for_team(&team()).unwrap();
    let mut contract = BuildContract {
        api_version: "zdn-build/v1alpha1".into(),
        source_sha256: "a".repeat(64),
        source_bytes: 1,
        revision: "b".repeat(40),
        recipe: BuildRecipe {
            dockerfile: "docker/Dockerfile".into(),
            context: ".".into(),
            target: "runtime".into(),
        },
        platform: "linux/amd64".into(),
        required_capabilities: Default::default(),
    };
    let exporter = NativeExporter {
        protocol: zdn::build_export::PROTOCOL.into(),
        helper: zdn::devnet::Artifact {
            sha256: "e".repeat(64),
            bytes: 128,
        },
        version: Some("runtime-version".into()),
    };
    let render = |contract: &BuildContract, infra: &BuildInfrastructure, attempt| -> Value {
        serde_json::from_str(
            &native_buildspec(contract, infra, attempt, "pinned-version", &exporter).unwrap(),
        )
        .unwrap()
    };
    let first = render(&contract, &infra, uuid::Uuid::nil());
    contract.source_sha256 = "c".repeat(64);
    contract.revision = "d".repeat(40);
    let changed = render(&contract, &infra, uuid::Uuid::new_v4());
    assert_ne!(first["cache"]["key"], changed["cache"]["key"]);
    assert_eq!(
        first["cache"]["fallback-keys"],
        changed["cache"]["fallback-keys"]
    );
    assert_eq!(first["cache"]["paths"], changed["cache"]["paths"]);
    let prefix = first["cache"]["fallback-keys"][0].as_str().unwrap();
    assert!(prefix.starts_with(&infra.project_name));
    assert!(prefix.contains("linux-amd64-standard7-buildx-local-v1"));
    assert!(first["cache"]["key"].as_str().unwrap().starts_with(prefix));
    contract.recipe.dockerfile = "Dockerfile".into();
    assert_ne!(
        first["cache"]["paths"],
        render(&contract, &infra, uuid::Uuid::nil())["cache"]["paths"]
    );
    let mut other = team();
    other.team_id = "other".into();
    assert_ne!(
        first["cache"]["fallback-keys"],
        render(
            &contract,
            &BuildInfrastructure::for_team(&other).unwrap(),
            uuid::Uuid::nil()
        )["cache"]["fallback-keys"]
    );
    let script = first["phases"]["build"]["commands"][0].as_str().unwrap();
    for required in [
        "--driver docker-container",
        "--cache-from",
        "type=local,src=$cache_dir",
        "--cache-to",
        "type=local,dest=$cache_next,mode=max,ignore-error=true",
        "--push",
        "get-download-url-for-layer",
        "--config-download config-download.json",
        "--version-id 'pinned-version'",
        "./zdn-runtime __build-export",
    ] {
        assert!(script.contains(required), "missing {required}");
    }
    for removed in ["--load", "--no-cache", "docker save", "docker push"] {
        assert!(!script.contains(removed), "unexpected {removed}");
    }
    assert!(
        script.find("--body output/").unwrap()
            < script.find("mv \"$cache_next\" \"$cache_dir\"").unwrap()
    );
    assert_eq!(
        first["phases"]["build"]["commands"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let mut unsafe_infra = infra;
    unsafe_infra.project_name = "../../outside".into();
    assert!(native_buildspec(
        &contract,
        &unsafe_infra,
        uuid::Uuid::nil(),
        "version",
        &exporter,
    )
    .is_err());
}
