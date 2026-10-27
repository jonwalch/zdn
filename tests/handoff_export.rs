use serde_json::{json, Value};
use uuid::Uuid;
use zdn::{
    handoff::export::export,
    ssm::validate_handoff,
    state::{BindingContext, Scope, StateStore},
};

const INSTANCE: &str = "i-0123456789abcdef0";
const SCRIPT: &str = "printf '%s' '{\"ready\":true}'";

fn attempt(state: &str) -> Value {
    let id = Uuid::new_v4();
    json!({"id":id,"createdAt":1800000000,"comment":format!("zdn-command-{id}"),
        "commandId":Uuid::new_v4(),"state":state,"uncertain":false,
        "cancellationRequested":true,"failure":null,"output":{"ready":true}})
}

fn journal() -> Value {
    let mut failed = attempt("failed");
    failed["failure"] = json!("cancelled");
    failed["output"] = Value::Null;
    let request = json!({"DocumentName":"AWS-RunShellScript","DocumentVersion":"1","InstanceIds":[INSTANCE],
        "TimeoutSeconds":120,"MaxConcurrency":"1","MaxErrors":"0", "CloudWatchOutputConfig":{"CloudWatchOutputEnabled":false},
        "Parameters":{"commands":[SCRIPT],"executionTimeout":["300"],"workingDirectory":["/"]}});
    json!({"apiVersion":"zdn-ssm-command/v1alpha1","requestSha256":zdn::devnet::sha256(&serde_json::to_vec(&request).unwrap()),
        "instanceId":INSTANCE,"timeoutSecs":300,"attempts":[failed,attempt("succeeded")]})
}

fn valid(value: &Value) -> bool {
    validate_handoff(&serde_json::to_vec(value).unwrap(), INSTANCE, SCRIPT, 300).is_ok()
}

#[test]
fn terminal_histories_and_cancellation_flags_are_portable() {
    let value = journal();
    assert!(valid(&value));
    let mut rejected = value.clone();
    rejected["attempts"][0]["failure"] = json!("request-rejected");
    rejected["attempts"][0]["commandId"] = Value::Null;
    assert!(valid(&rejected));
    for field in ["instanceId", "apiVersion", "requestSha256"] {
        let mut invalid = value.clone();
        invalid[field] = json!("invalid");
        assert!(!valid(&invalid), "accepted invalid {field}");
    }
    for timeout in [0, 29, 301, 7201] {
        let mut invalid = value.clone();
        invalid["timeoutSecs"] = json!(timeout);
        assert!(!valid(&invalid));
    }
    assert!(validate_handoff(
        &serde_json::to_vec(&value).unwrap(),
        INSTANCE,
        "other command",
        300
    )
    .is_err());
    assert!(validate_handoff(&vec![b' '; 128 * 1024 + 1], INSTANCE, SCRIPT, 300).is_err());
}

#[test]
fn in_flight_and_uncertain_attempts_cannot_be_handed_off() {
    for state in ["prepared", "dispatched", "running"] {
        let mut value = journal();
        let current = &mut value["attempts"][1];
        current["state"] = json!(state);
        current["output"] = Value::Null;
        current["cancellationRequested"] = json!(false);
        if state != "running" {
            current["commandId"] = Value::Null;
        }
        if state == "dispatched" {
            current["uncertain"] = json!(true);
        }
        assert!(!valid(&value), "accepted {state}");
    }
    let mut value = journal();
    value["attempts"][0]["uncertain"] = json!(true);
    assert!(!valid(&value));
    value = journal();
    value["attempts"][1]["commandId"] = value["attempts"][0]["commandId"].clone();
    assert!(!valid(&value));
}

#[test]
fn export_of_missing_deployment_does_not_create_it() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let config = source.join("devnet.yaml");
    std::fs::write(&config, "name: feature\n").unwrap();
    let context = BindingContext::new(
        config,
        None,
        None,
        Scope {
            team_id: "test-team".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        },
    )
    .unwrap();
    let store = StateStore::open(root.path().join("state")).unwrap();
    let binding = store.bind(&context, "feature").unwrap();
    let output = root.path().join("handoff.tar");
    assert!(export(&store, &binding, &output).is_err());
    assert!(!store.root().join("foundation").exists());
    assert!(!output.exists());
}
