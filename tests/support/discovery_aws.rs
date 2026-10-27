//! Data-only AWS fixture. Re-executes this test binary, never a real AWS tool.

use super::native_tool;
use eyre::{bail, ensure, ContextCompat, Result};
use fs2::FileExt;
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

pub fn install(path: &Path) {
    native_tool::install(path, "discovery_aws::worker", &json!({}));
}

fn read_json(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn response(root: &Path, args: &[String], mode: &str, parent: i32) -> Result<Value> {
    let index = args
        .iter()
        .position(|s| ["sts", "ssm", "s3api", "ec2", "iam"].contains(&s.as_str()))
        .context("unknown fixture service")?;
    let service = args[index].as_str();
    let operation = args.get(index + 1).context("missing fixture operation")?;
    let mut input = match args.iter().position(|s| s == "--cli-input-json") {
        Some(index) => serde_json::from_str(args.get(index + 1).context("missing fixture input")?)?,
        None => json!({}),
    };
    let mut log = OpenOptions::new()
        .append(true)
        .create(true)
        .open(root.join("calls.jsonl"))?;
    // Inventory workers append concurrently; keep each JSON record intact.
    log.lock_exclusive()?;
    writeln!(
        log,
        "{}",
        json!({"service":service,"operation":operation,"input":input})
    )?;
    FileExt::unlock(&log)?;

    let absent = |code: &str| -> Result<Value> {
        bail!("An error occurred ({code}) when calling fixture: SECRET")
    };
    match (service, operation.as_str()) {
        ("sts", "get-caller-identity") => {
            let profile = read_json(&root.join("state/profiles/local.json"))?;
            let role = profile["team"]["deployment"]["roleArn"]
                .as_str()
                .context("missing fixture role")?
                .rsplit('/')
                .next()
                .unwrap();
            Ok(json!({"Account":"123456789012", "UserId":"fixture",
                "Arn":format!("arn:aws:sts::123456789012:assumed-role/{role}/fixture")}))
        }
        ("ssm", "send-command") if mode != "status" => {
            let reports = read_json(&root.join("reports.json"))?;
            let report = &reports[input["InstanceIds"][0]
                .as_str()
                .context("missing fixture instance")?];
            let network: uuid::Uuid = report["deploymentId"]
                .as_str()
                .context("missing fixture deployment")?
                .parse()?;
            let deployment: zdn::foundation::Deployment = serde_json::from_value(read_json(
                &root.join(format!("state/foundation/{network}/deployment.json")),
            )?)?;
            let node = report["nodeId"].as_str().context("missing fixture node")?;
            let host = deployment
                .cluster
                .as_ref()
                .context("missing fixture cluster")?
                .host_spec(
                    &deployment.spec,
                    &deployment.team,
                    &deployment
                        .outputs
                        .as_ref()
                        .context("missing fixture outputs")?
                        .nodes[node],
                )?;
            let manifest = zdn::host::runtime::Manifest::new(
                host.clone(),
                zdn::host::runtime::Selection {
                    protocol: zdn::host::runtime::PROTOCOL.into(),
                    helper: host.helper.clone(),
                },
            )?;
            let command = format!(
                "/etc/zdn/runtime/{}/zdn __host-runtime --protocol {} --manifest /etc/zdn/runtime/manifests/{} observe",
                manifest.runtime.helper.sha256,
                zdn::host::runtime::PROTOCOL,
                manifest.file_name()?,
            );
            ensure!(
                input["Parameters"]["commands"] == json!([command]),
                "unexpected fixture host command"
            );
            if mode == "denied" {
                return absent("AccessDeniedException");
            }
            let id = uuid::Uuid::new_v4();
            input["CommandId"] = json!(id);
            fs::write(root.join(format!("{id}.json")), serde_json::to_vec(&input)?)?;
            Ok(json!({"Command":input}))
        }
        ("ssm", "get-command-invocation") if mode != "status" => {
            let id: uuid::Uuid = input["CommandId"]
                .as_str()
                .context("missing fixture command ID")?
                .parse()?;
            let command = read_json(&root.join(format!("{id}.json")))?;
            let reports = read_json(&root.join("reports.json"))?;
            let mut report = reports
                .get(
                    input["InstanceId"]
                        .as_str()
                        .context("missing fixture instance")?,
                )
                .context("unknown fixture instance")?
                .clone();
            if matches!(mode, "not-ready" | "timeout") {
                report["scheduledProducer"] = json!(false);
                report["producer"] = Value::Null;
            }
            let mut result = json!({"InstanceId":input["InstanceId"],"Status":"Success",
                "ResponseCode":0,"StandardOutputContent":serde_json::to_string(&report)?,
                "StandardErrorContent":"SECRET"});
            for key in ["CommandId", "DocumentName", "DocumentVersion", "Comment"] {
                result[key] = command[key].clone();
            }
            if mode == "cancelled" {
                // The shell launcher is an extra process. Signal the original
                // zdn caller, not the worker's immediate shell parent.
                ensure!(parent > 1, "invalid fixture caller PID");
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(parent),
                    nix::sys::signal::Signal::SIGTERM,
                )?;
            }
            Ok(result)
        }
        ("s3api", "get-object") if mode == "status" => absent("NoSuchKey"),
        ("iam", "get-role" | "get-instance-profile") if mode == "status" => absent("NoSuchEntity"),
        ("ec2", operation) if mode == "status" => {
            let (key, ids, code) = match operation {
                "describe-instances" => {
                    ("Reservations", "InstanceIds", "InvalidInstanceID.NotFound")
                }
                "describe-vpcs" => ("Vpcs", "VpcIds", "InvalidVpcID.NotFound"),
                "describe-addresses" => {
                    ("Addresses", "AllocationIds", "InvalidAllocationID.NotFound")
                }
                "describe-subnets" => ("Subnets", "SubnetIds", "InvalidSubnetID.NotFound"),
                "describe-security-groups" => {
                    ("SecurityGroups", "GroupIds", "InvalidGroup.NotFound")
                }
                "describe-internet-gateways" => ("InternetGateways", "", ""),
                "describe-route-tables" => ("RouteTables", "", ""),
                "describe-nat-gateways" => ("NatGateways", "NatGatewayIds", "NatGatewayNotFound"),
                "describe-volumes" => ("Volumes", "VolumeIds", "InvalidVolume.NotFound"),
                _ => bail!("unexpected fixture operation"),
            };
            if !ids.is_empty() && input.get(ids).is_some() {
                return absent(code);
            }
            let mut result = json!({});
            result[key] = if operation == "describe-instances" {
                json!([{"Instances":[{"InstanceId":"i-00000000000000002","State":{"Name":"running"}}]}])
            } else {
                json!([])
            };
            Ok(result)
        }
        _ => bail!("unexpected fixture operation"),
    }
}

#[test]
fn worker() {
    let Some((work, args, _)) = native_tool::invocation() else {
        return;
    };
    let version = args == ["--version"];
    let result = if version {
        Ok("aws-cli/2.37.4 fixture".into())
    } else {
        response(
            Path::new(&std::env::var_os("ZDN_DISCOVERY_FIXTURE").unwrap()),
            &args,
            &std::env::var("ZDN_DISCOVERY_MODE").unwrap(),
            std::env::var("ZDN_TEST_CALLER").unwrap().parse().unwrap(),
        )
        .map(|value| serde_json::to_string(&value).unwrap())
    };
    let (stdout, stderr, code) = match result {
        Ok(value) => (
            format!("{value}\n"),
            if version {
                String::new()
            } else {
                "SECRET\n".into()
            },
            0,
        ),
        Err(error) => (String::new(), format!("{error}\n"), 1),
    };
    native_tool::reply(&work, stdout.as_bytes(), stderr.as_bytes(), code);
}

#[test]
fn unexpected_operations_fail_without_falling_through_to_a_real_tool() {
    let root = tempfile::Builder::new()
        .prefix("discovery ' space ")
        .tempdir()
        .unwrap();
    let aws = root.path().join("aws");
    install(&aws);
    let input = json!({"InstanceIds":["i-unexpected"],"literal":"a ' quoted value"});
    let output = std::process::Command::new(aws)
        .env_clear()
        .env("ZDN_DISCOVERY_FIXTURE", root.path())
        .env("ZDN_DISCOVERY_MODE", "status")
        .args([
            "ec2",
            "terminate-instances",
            "--cli-input-json",
            &input.to_string(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"unexpected fixture operation\n");
    let call = read_json(&root.path().join("calls.jsonl")).unwrap();
    assert_eq!(call["operation"], "terminate-instances");
    assert_eq!(call["input"], input);
}
