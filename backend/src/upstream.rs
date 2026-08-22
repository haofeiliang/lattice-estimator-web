//! Typed HTTP client and wire protocol for the sibling lattice-estimator API.
//!
//! This is the only backend module that knows the estimator service's JSON contract.

use std::time::Duration;

use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::{
    Attack, DurationScope, EstimatorContext, EstimatorProblem, ExactDecimal, NormalizedMetric,
    ReductionCostModel, ReductionShapeModel, ResolvedAnalysisSettings, error::ServiceError,
};

#[derive(Clone)]
/// Reusable HTTP client for lattice-estimator-api.
pub struct EstimatorClient {
    client: reqwest::Client,
    base_url: Url,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Capability and provenance metadata returned by lattice-estimator-api.
pub struct Metadata {
    pub adapter_schema_version: u64,
    pub estimator_commit: String,
    pub sage_version: String,
    pub adapter_version: String,
    pub worker_image: String,
    pub platform: String,
    pub support_matrix: serde_json::Value,
    pub adaptive_attacks: Vec<Attack>,
    #[serde(default)]
    pub slow_attack_applicability_rule_version: u32,
}

impl Metadata {
    /// Extract fields that participate in exact-result cache identity.
    pub fn context(&self) -> EstimatorContext {
        EstimatorContext {
            estimator_commit: self.estimator_commit.clone(),
            sage_version: self.sage_version.clone(),
            adapter_version: self.adapter_version.clone(),
            worker_image: self.worker_image.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
/// Exact or preflight request sent to one estimator-api Sage worker.
pub struct WorkerRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<&'static str>,
    pub schema_version: u32,
    pub problem: EstimatorProblem,
    pub models: WorkerModels,
    pub target_attacks: Vec<Attack>,
    pub timeout_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_security_bits: Option<ExactDecimal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_arora_gb_coarse_margin_bits: Option<ExactDecimal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_arora_gb_refined_margin_bits: Option<ExactDecimal>,
}

impl WorkerRequest {
    /// Build an exact request with resolved analysis settings and attack order.
    pub fn new(
        problem: EstimatorProblem,
        analysis: &ResolvedAnalysisSettings,
        target_attacks: Vec<Attack>,
        timeout_seconds: u64,
    ) -> Self {
        Self {
            operation: None,
            schema_version: 4,
            problem,
            models: WorkerModels {
                cost_model: analysis.cost_model,
                shape_model: analysis.shape_model,
            },
            target_attacks,
            timeout_seconds,
            required_security_bits: None,
            requested_arora_gb_coarse_margin_bits: None,
            requested_arora_gb_refined_margin_bits: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
/// Upstream reduction cost and shape selections.
pub struct WorkerModels {
    pub cost_model: ReductionCostModel,
    pub shape_model: ReductionShapeModel,
}

#[derive(Clone, Debug, Deserialize)]
/// Validated estimator-api response before conversion to report outcomes.
pub struct WorkerResponse {
    pub results: Vec<WorkerAttackExecution>,
    pub duration_ms: u64,
    pub provenance: WorkerProvenance,
}

#[derive(Clone, Debug, Deserialize)]
/// Estimator-api provenance attached to an HTTP response.
pub struct WorkerProvenance {
    pub estimator_commit: String,
    pub sage_version: String,
    pub adapter_version: String,
    pub worker_image: String,
}

#[derive(Clone, Debug, Deserialize)]
/// One timed attack result returned by the estimator worker.
pub struct WorkerAttackExecution {
    pub attack: Attack,
    pub outcome: WorkerOutcome,
    pub duration_ms: u64,
    pub duration_scope: DurationScope,
    pub shared_attacks: Vec<Attack>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// Tagged estimator-api outcome variants consumed by the scheduler.
pub enum WorkerOutcome {
    Computed {
        security_bits: ExactDecimal,
        #[serde(default)]
        metrics: std::collections::BTreeMap<String, NormalizedMetric>,
    },
    NoFiniteEstimate {
        code: String,
        reason: String,
        #[serde(default)]
        raw_result: Option<serde_json::Value>,
    },
    PreflightUnknown {
        code: String,
        reason: String,
        #[serde(default)]
        raw_result: Option<serde_json::Value>,
    },
    ThresholdScreen {
        decision: WorkerThresholdDecision,
        precision_tier: WorkerPrecisionTier,
        required_security_bits: ExactDecimal,
        requested_margin_bits: ExactDecimal,
        calibrated_margin_floor_bits: ExactDecimal,
        effective_margin_bits: ExactDecimal,
        decision_threshold_bits: ExactDecimal,
        reason: String,
        #[serde(default)]
        metrics: std::collections::BTreeMap<String, NormalizedMetric>,
    },
    Unsupported {
        code: String,
        reason: String,
    },
    Failed {
        code: String,
        message: String,
        retryable: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Target-aware Arora threshold-screen decision.
pub enum WorkerThresholdDecision {
    AboveThreshold,
    NeedsExact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Arora v6 search tier that completed the decision.
pub enum WorkerPrecisionTier {
    Coarse,
    Refined,
}

impl EstimatorClient {
    /// Validate a base URL and configure bounded HTTP connect timeouts.
    pub fn new(base_url: &str) -> Result<Self, ServiceError> {
        let base_url = Url::parse(base_url)
            .map_err(|error| ServiceError::BadRequest(format!("invalid estimator URL: {error}")))?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        Ok(Self { client, base_url })
    }

    /// Fetch estimator versions and the supported-domain matrix.
    pub async fn metadata(&self) -> Result<Metadata, ServiceError> {
        let url = self
            .base_url
            .join("v1/metadata")
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| ServiceError::Upstream(error.to_string()))?;
        decode(response).await
    }

    /// Execute the requested exact attack group.
    pub async fn estimate(&self, request: &WorkerRequest) -> Result<WorkerResponse, ServiceError> {
        let url = self
            .base_url
            .join("v1/estimate")
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let response = self
            .client
            .post(url)
            .json(request)
            .send()
            .await
            .map_err(|error| ServiceError::Upstream(error.to_string()))?;
        decode(response).await
    }

    /// Execute slow-attack preflight logic without exact attacks.
    pub async fn preflight(&self, request: &WorkerRequest) -> Result<WorkerResponse, ServiceError> {
        let url = self
            .base_url
            .join("v1/preflight")
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let mut request = request.clone();
        request.operation = Some("preflight");
        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .await
            .map_err(|error| ServiceError::Upstream(error.to_string()))?;
        decode(response).await
    }
}

async fn decode<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, ServiceError> {
    // Preserve upstream error bodies for diagnosis, but deserialize successful
    // responses into the strict Rust protocol before the scheduler sees them.
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| ServiceError::Upstream(error.to_string()))?;
    if !status.is_success() {
        let detail = String::from_utf8_lossy(&bytes);
        if status == reqwest::StatusCode::GATEWAY_TIMEOUT {
            return Err(ServiceError::UpstreamTimeout(detail.into_owned()));
        }
        return Err(ServiceError::Upstream(format!(
            "worker returned {status}: {}",
            &detail[..detail.len().min(2_048)]
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| ServiceError::Upstream(format!("invalid worker response: {error}")))
}
