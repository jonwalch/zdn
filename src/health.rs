//! Explicit fresh observations, separate from deployment and payment qualification.
use crate::{aws::AwsApi, foundation::Deployment, foundation_live::Runtime};
use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, sync::atomic::AtomicBool};
use uuid::Uuid;

pub const API_VERSION: &str = "zdn-health/v1alpha1";

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub wait: bool,
    pub timeout_secs: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            wait: false,
            timeout_secs: 120,
        }
    }
}

impl Options {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=7200).contains(&self.timeout_secs),
            "health timeout must be between 1 and 7200 seconds"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Ready,
    NotReady,
    Unavailable,
    Invalid,
    Unchecked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Check {
    pub status: Status,
    pub observed_at: Option<u64>,
    pub fresh: bool,
    pub code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub api_version: String,
    pub network_id: Uuid,
    pub started_at: u64,
    pub checked_at: u64,
    pub attempts: u32,
    pub ready: bool,
    pub timed_out: bool,
    pub cancelled: bool,
    pub live_readiness_checked: bool,
    pub payment_qualification: String,
    pub launch_ready: bool,
    pub checks: BTreeMap<String, Check>,
}

/// Validate saved deployment proofs without credentials or cloud calls.
pub fn validate(deployment: &Deployment, directory: &Path, options: Options) -> Result<()> {
    crate::foundation_live::health::validate(deployment, directory, options)
}

/// Issue only observation commands; never install, start services or reconcile.
/// Individual API calls must honor the remaining timeout supplied by the adapter.
pub fn check(
    api: &dyn AwsApi,
    deployment: &Deployment,
    directory: &Path,
    options: Options,
    runtime: &impl Runtime,
    cancel: &AtomicBool,
) -> Result<Report> {
    crate::foundation_live::health::check(api, deployment, directory, options, runtime, cancel)
}
