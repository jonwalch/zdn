//! Data-only source-build CLI responses; never invokes AWS or a real builder.

use super::native_tool;
use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::{bail, ContextCompat, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, fs::OpenOptions, io::Write, path::Path};

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read_json(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn flag<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    let index = args
        .iter()
        .position(|arg| arg == name)
        .context("missing fixture flag")?;
    Ok(args.get(index + 1).context("missing fixture flag value")?)
}

fn absent(code: &str, operation: &str) -> eyre::Report {
    eyre::eyre!(
        "An error occurred ({code}) when calling the {operation} operation: fixture failure"
    )
}

fn response(root: &Path, f: &Value, args: &[String]) -> Result<Value> {
    let index = args
        .iter()
        .position(|arg| arg == "--cli-read-timeout")
        .context("missing fixture timeout")?;
    let service = args.get(index + 2).context("missing fixture service")?;
    let operation = args.get(index + 3).context("missing fixture operation")?;
    writeln!(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("calls"))?,
        "{service}.{operation}"
    )?;
    let data: Value = if args.iter().any(|arg| arg == "--cli-input-json") {
        serde_json::from_str(flag(args, "--cli-input-json")?)?
    } else {
        json!({})
    };
    let project = f["project"].as_str().unwrap();
    let id = format!("{project}:00000000-0000-4000-8000-000000000001");
    let mut build = json!({"id":id,"projectName":project,"arn":format!("arn:aws:codebuild:us-east-1:123456789012:build/{id}")});
    let configured = std::env::var("ZDN_MODE")?;
    let mode = if root.join("retry").exists() {
        if configured == "uncertain-publication" {
            "publication-uncertain".into()
        } else {
            "valid".into()
        }
    } else {
        configured
    };
    if root.join("started.json").exists() {
        build["source"] =
            json!({"buildspec":read_json(&root.join("started.json"))?["buildspecOverride"]});
    }
    if service == "sts" && root.join("login-denied").exists() {
        bail!("aws: [ERROR]: Your session has expired. fixture-secret-do-not-disclose");
    }
    match (service.as_str(), operation.as_str()) {
        ("sts", "get-caller-identity") => Ok(
            json!({"Account":"123456789012","Arn":format!("arn:aws:sts::123456789012:assumed-role/{}/fixture",f["roleName"].as_str().unwrap()),"UserId":"fixture"}),
        ),
        ("codebuild", "batch-get-projects") => Ok(
            json!({"projectsNotFound":[],"projects":[{"name":project,"arn":format!("arn:aws:codebuild:us-east-1:123456789012:project/{project}"),"environment":{"type":"LINUX_CONTAINER","image":"aws/codebuild/standard:7.0","computeType":"BUILD_GENERAL1_MEDIUM","privilegedMode":true},"source":{"type":"NO_SOURCE"},"artifacts":{"type":"NO_ARTIFACTS"},"cache":{"type":"S3","location":format!("{}/cache",f["bucket"].as_str().unwrap()),"cacheNamespace":project}}]}),
        ),
        ("s3api", "put-object") => {
            let content = fs::read(flag(args, "--body")?)?;
            assert_eq!(
                Sha256::digest(&content).as_slice(),
                STANDARD.decode(data["ChecksumSHA256"].as_str().unwrap())?
            );
            if data["Key"].as_str().unwrap().starts_with("images/") {
                assert_eq!(data["IfNoneMatch"], "*");
                if root.join("index.json").exists() {
                    return Err(absent("PreconditionFailed", "PutObject"));
                }
                fs::write(root.join("index.json"), content)?;
                if mode == "publication-uncertain" {
                    return Err(absent("ServiceUnavailableException", "PutObject"));
                }
            }
            Ok(
                json!({"VersionId":"fixture-version","ChecksumSHA256":data["ChecksumSHA256"],"ServerSideEncryption":"AES256"}),
            )
        }
        ("codebuild", "start-build") => {
            fs::write(root.join("started.json"), serde_json::to_vec(&data)?)?;
            if matches!(mode.as_str(), "uncertain" | "uncertain-publication") {
                return Err(absent("ServiceUnavailableException", "StartBuild"));
            }
            build["source"] = json!({"buildspec":data["buildspecOverride"]});
            Ok(json!({"build":build}))
        }
        ("codebuild", "list-builds-for-project") => {
            assert_eq!(data["projectName"], project);
            Ok(json!({"ids":[id]}))
        }
        ("codebuild", "batch-get-builds") => {
            if mode == "interrupted" {
                return Err(absent("ServiceUnavailableException", "BatchGetBuilds"));
            }
            build["buildStatus"] = json!(if mode == "failed" {
                "FAILED"
            } else {
                "SUCCEEDED"
            });
            Ok(json!({"buildsNotFound":[],"builds":[build]}))
        }
        ("s3api", "get-object") if flag(args, "--key")?.starts_with("images/") => {
            if !root.join("index.json").exists() {
                return Err(absent("NoSuchKey", "GetObject"));
            }
            fs::copy(root.join("index.json"), args.last().unwrap())?;
            Ok(json!({"ServerSideEncryption":"AES256"}))
        }
        ("s3api", "get-object") | ("ecr", "batch-get-image") => {
            let started = read_json(&root.join("started.json"))?;
            let spec: Value = serde_json::from_str(started["buildspecOverride"].as_str().unwrap())?;
            let script = spec["phases"]["build"]["commands"][0].as_str().unwrap();
            // Decode the saved request, not an in-memory production BuildContract.
            let encoded = ["base64.b64decode('", "printf '%s' '"]
                .into_iter()
                .find_map(|prefix| script.split_once(prefix).map(|(_, tail)| tail))
                .context("missing encoded contract")?
                .split_once('\'')
                .context("unterminated encoded contract")?
                .0;
            let raw = STANDARD.decode(encoded)?;
            let c: Value = serde_json::from_slice(&raw)?;
            let manifest = f["manifest"].as_str().unwrap();
            let digest = format!("sha256:{}", hash(manifest.as_bytes()));
            if service == "ecr" {
                return Ok(
                    json!({"failures":[],"images":[{"imageId":{"imageDigest":digest},"imageManifest":manifest}]}),
                );
            }
            let manifest_json: Value = serde_json::from_str(manifest)?;
            let image = json!({"apiVersion":"zdn-zakura-image/v1alpha1","image":format!("{}@{digest}",f["uri"].as_str().unwrap()),"configDigest":manifest_json["config"]["digest"],"platform":c["platform"],"provenance":{"kind":"source","revision":c["revision"],"snapshotSha256":c["sourceSha256"]},"capabilities":c["requiredCapabilities"],"binaryPath":"/usr/local/bin/zakurad","environmentLauncher":"/usr/bin/env"});
            let key = flag(args, "--key")?;
            let name = key.rsplit('/').next().unwrap();
            let content = match name {
                "result.json" => {
                    serde_json::to_string(&json!({"contractSha256":hash(&raw),"image":image}))?
                }
                "image-manifest.json" => manifest.into(),
                "image-config.json" if mode == "corrupt" => "{}".into(),
                "image-config.json" => f["config"].as_str().unwrap().into(),
                _ => bail!("unexpected fixture object"),
            };
            fs::write(args.last().unwrap(), content)?;
            Ok(json!({"ServerSideEncryption":"AES256"}))
        }
        _ => bail!("unexpected AWS action: {service}.{operation}"),
    }
}

#[test]
fn worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let result = if args == ["--version"] {
        Ok("aws-cli/2.37.4 fixture".into())
    } else {
        response(
            Path::new(payload["root"].as_str().unwrap()),
            &payload,
            &args,
        )
        .map(|value| value.to_string())
    };
    match result {
        Ok(value) => native_tool::reply(&work, format!("{value}\n").as_bytes(), b"", 0),
        Err(error) => native_tool::reply(&work, b"", format!("{error}\n").as_bytes(), 1),
    }
}
