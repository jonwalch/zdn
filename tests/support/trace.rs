//! Isolated production-style tracing for public runtime fixture tests.
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process::Command,
    sync::Mutex,
};

use serde_json::Value;
use tracing_subscriber::{filter::filter_fn, fmt::format::FmtSpan, prelude::*};

pub struct Trace {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

pub fn capture(test: &str) -> Option<Trace> {
    if std::env::var("ZDN_TRACE_TEST").as_deref() != Ok(test) {
        // Avoid global callsite/subscriber races with the rest of libtest.
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("ZDN_TRACE_TEST", test)
            .status()
            .unwrap();
        assert!(status.success(), "isolated trace test failed: {test}");
        return None;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("trace.jsonl");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(Mutex::new(file))
                .with_span_events(FmtSpan::CLOSE)
                .with_filter(filter_fn(|metadata| {
                    metadata.is_span()
                        && (metadata.target() == "zdn" || metadata.target().starts_with("zdn::"))
                })),
        )
        .try_init()
        .unwrap();
    Some(Trace {
        _directory: directory,
        path,
    })
}

impl Trace {
    pub fn assert_spans(&self, required: &[&str], private: &[&str]) {
        let text = fs::read_to_string(&self.path).unwrap();
        for secret in private {
            assert!(!text.contains(secret), "private data in trace");
        }
        let records: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for name in required {
            let spans: Vec<_> = records
                .iter()
                .filter(|record| record["span"]["name"] == *name)
                .collect();
            assert!(!spans.is_empty(), "missing span: {name}");
            for record in spans {
                assert_eq!(record["span"].as_object().unwrap().len(), 1, "{name}");
                assert!(record["fields"]["time.busy"].is_string(), "{name}");
                assert!(record["fields"]["time.idle"].is_string(), "{name}");
            }
        }
    }

    pub fn assert_child(&self, child: &str, parent: &str) {
        let text = fs::read_to_string(&self.path).unwrap();
        assert!(
            text.lines().any(|line| {
                let record: Value = serde_json::from_str(line).unwrap();
                record["span"]["name"] == child
                    && record["spans"]
                        .as_array()
                        .is_some_and(|spans| spans.iter().any(|span| span["name"] == parent))
            }),
            "{child} must be nested in {parent}"
        );
    }
}
