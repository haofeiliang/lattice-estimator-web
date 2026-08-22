//! Core parameter, distribution, attack, analysis, timing, and outcome types.
//!
//! Shared by persistence, scheduling, public formats, and the estimator adapter.

use std::{collections::BTreeMap, fmt, str::FromStr};

use bigdecimal::BigDecimal;
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::validation::ValidationError;

/// A canonical unsigned decimal integer serialized as a JSON string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct PositiveInteger(#[schemars(regex(pattern = r"^(0|[1-9][0-9]*)$"))] String);

impl PositiveInteger {
    /// Parse and canonicalize a non-negative base-10 integer string.
    pub fn new(value: impl AsRef<str>) -> Result<Self, String> {
        let value = value.as_ref();
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("expected an unsigned base-10 integer string".into());
        }
        let normalized = value.trim_start_matches('0');
        Ok(Self(if normalized.is_empty() {
            "0".into()
        } else {
            normalized.into()
        }))
    }

    /// Borrow the canonical decimal representation used on the wire.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert the validated value to an arbitrary-precision integer.
    pub fn as_biguint(&self) -> BigUint {
        BigUint::from_str(&self.0).expect("validated decimal integer")
    }
}

impl<'de> Deserialize<'de> for PositiveInteger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

impl fmt::Display for PositiveInteger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A canonical signed decimal integer serialized as a JSON string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct SignedInteger(#[schemars(regex(pattern = r"^(0|-?[1-9][0-9]*)$"))] String);

impl SignedInteger {
    /// Parse and canonicalize a signed base-10 integer string.
    pub fn new(value: impl AsRef<str>) -> Result<Self, String> {
        let value = value.as_ref();
        let (negative, digits) = match value.strip_prefix('-') {
            Some(digits) => (true, digits),
            None => (false, value),
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("expected a signed base-10 integer string".into());
        }
        let normalized = digits.trim_start_matches('0');
        if normalized.is_empty() {
            return Ok(Self("0".into()));
        }
        Ok(Self(if negative {
            format!("-{normalized}")
        } else {
            normalized.into()
        }))
    }

    /// Convert the validated value to an arbitrary-precision signed integer.
    pub fn as_bigint(&self) -> BigInt {
        BigInt::from_str(&self.0).expect("validated signed integer")
    }
}

impl<'de> Deserialize<'de> for SignedInteger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A canonical, finite base-10 decimal serialized as a JSON string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ExactDecimal(
    #[schemars(regex(pattern = r"^(?:0|-?(?:0\.[0-9]*[1-9]|[1-9][0-9]*(?:\.[0-9]*[1-9])?))$"))]
    String,
);

impl ExactDecimal {
    /// Parse a finite plain decimal and remove redundant zeros.
    pub fn new(value: impl AsRef<str>) -> Result<Self, String> {
        let value = value.as_ref();
        if value.is_empty() || value.starts_with('+') || value.contains(['e', 'E']) {
            return Err(
                "expected a plain finite base-10 decimal string without an exponent".into(),
            );
        }
        let (negative, unsigned) = match value.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, value),
        };
        let mut pieces = unsigned.split('.');
        let integer = pieces.next().unwrap_or_default();
        let fraction = pieces.next();
        if pieces.next().is_some()
            || integer.is_empty()
            || !integer.bytes().all(|byte| byte.is_ascii_digit())
            || fraction.is_some_and(|part| {
                part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err("expected a plain finite base-10 decimal string".into());
        }

        let integer = integer.trim_start_matches('0');
        let integer = if integer.is_empty() { "0" } else { integer };
        let fraction = fraction
            .map(|part| part.trim_end_matches('0'))
            .unwrap_or_default();
        let is_zero = integer == "0" && fraction.is_empty();
        let sign = if negative && !is_zero { "-" } else { "" };
        let normalized = if fraction.is_empty() {
            format!("{sign}{integer}")
        } else {
            format!("{sign}{integer}.{fraction}")
        };
        Ok(Self(normalized))
    }

    /// Borrow the canonical non-exponent decimal representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert the validated value without binary floating-point loss.
    pub fn as_big_decimal(&self) -> BigDecimal {
        BigDecimal::from_str(&self.0).expect("validated exact decimal")
    }

    /// Return whether the exact value is strictly greater than zero.
    pub fn is_positive(&self) -> bool {
        self.as_big_decimal() > BigDecimal::zero()
    }
}

impl<'de> Deserialize<'de> for ExactDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

impl fmt::Display for ExactDecimal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Finite or estimator-defined unlimited sample availability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SampleCount {
    Finite { count: u64 },
    Unlimited,
}

/// Negacyclic polynomial ring metadata retained for structured problems.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegacyclicRing {
    #[schemars(range(min = 1))]
    pub polynomial_degree: u64,
    pub ciphertext_modulus: PositiveInteger,
}

/// Supported secret-coefficient distributions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretDistribution {
    UniformBinary,
    UniformTernary,
    /// Independent coefficients with P(-1)=1/4, P(0)=1/2, and P(1)=1/4.
    SparseTernary {},
    FixedWeightBinary {
        hamming_weight: u64,
    },
    FixedWeightTernary {
        positive_weight: u64,
        negative_weight: u64,
    },
    DiscreteGaussian {
        standard_deviation: ExactDecimal,
    },
    CenteredBinomial {
        eta: u64,
    },
    UniformInteger {
        lower: SignedInteger,
        upper: SignedInteger,
    },
}

/// Supported error-coefficient distributions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ErrorDistribution {
    DiscreteGaussian {
        standard_deviation: ExactDecimal,
    },
    CenteredBinomial {
        eta: u64,
    },
    UniformInteger {
        lower: SignedInteger,
        upper: SignedInteger,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Unstructured LWE parameters.
pub struct LweProblem {
    #[schemars(range(min = 1))]
    pub dimension: u64,
    pub modulus: PositiveInteger,
    pub samples: SampleCount,
    pub secret: SecretDistribution,
    pub error: ErrorDistribution,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Ring-LWE parameters expressed using polynomial length and ring samples.
pub struct RlweProblem {
    pub negacyclic_ring: NegacyclicRing,
    pub samples: SampleCount,
    pub secret: SecretDistribution,
    pub error: ErrorDistribution,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// GLWE parameters with polynomial length and vector dimension kept distinct.
pub struct GlweProblem {
    pub negacyclic_ring: NegacyclicRing,
    #[schemars(range(min = 1))]
    pub dimension: u64,
    pub samples: SampleCount,
    pub secret: SecretDistribution,
    pub error: ErrorDistribution,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
/// Matrix or circulant interpretation of an NTRU instance.
pub enum NtruStructure {
    Matrix,
    Circulant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// NTRU parameters prior to reduction to the estimator's internal model.
pub struct NtruProblem {
    #[schemars(range(min = 1))]
    pub dimension: u64,
    pub modulus: PositiveInteger,
    pub secret: SecretDistribution,
    pub error: ErrorDistribution,
    pub structure: NtruStructure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
/// Norm used to interpret the SIS solution bound.
pub enum SisNorm {
    L2,
    LInfinity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Short-integer-solution instance parameters.
pub struct SisProblem {
    #[schemars(range(min = 1))]
    pub dimension: u64,
    pub modulus: PositiveInteger,
    #[schemars(range(min = 1))]
    pub columns: u64,
    pub length_bound: ExactDecimal,
    pub norm: SisNorm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Public problem variants accepted in parameter-set files and the UI.
pub enum Problem {
    Lwe(LweProblem),
    Rlwe(RlweProblem),
    Glwe(GlweProblem),
    Ntru(NtruProblem),
    Sis(SisProblem),
}

/// Problem variants accepted directly by the internal estimator adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EstimatorProblem {
    Lwe(LweProblem),
    Ntru(NtruProblem),
    Sis(SisProblem),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
/// Security interpretation attached to a parameter case.
pub enum SecurityModel {
    Classical,
    Quantum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
/// Lattice-reduction cost model selected for upstream estimation.
pub enum ReductionCostModel {
    #[serde(rename = "BDGL16")]
    Bdgl16,
    #[serde(rename = "LaaMosPol14")]
    LaaMosPol14,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
/// User-facing pairing of reduction cost and shape assumptions.
pub enum ReductionModel {
    CoefficientEmbeddingV1,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
/// Canonical attack identifiers used in scheduling, caching, and reports.
pub enum Attack {
    AroraGb,
    Bkw,
    Usvp,
    Bdd,
    BddHybrid,
    BddMitmHybrid,
    Dual,
    DualHybrid,
    Dsd,
    Lattice,
}

impl Attack {
    /// Canonical result order for LWE cases.
    pub const LWE: [Self; 8] = [
        Self::AroraGb,
        Self::Bkw,
        Self::Usvp,
        Self::Bdd,
        Self::BddHybrid,
        Self::BddMitmHybrid,
        Self::Dual,
        Self::DualHybrid,
    ];
    /// LWE attacks grouped into ordinary exact estimator requests.
    pub const LWE_FAST: [Self; 6] = [
        Self::Usvp,
        Self::Bdd,
        Self::BddHybrid,
        Self::BddMitmHybrid,
        Self::Dual,
        Self::DualHybrid,
    ];
    /// LWE attacks governed by dedicated preflight policy.
    pub const LWE_SLOW: [Self; 2] = [Self::AroraGb, Self::Bkw];
    /// Canonical result order for NTRU cases.
    pub const NTRU: [Self; 5] = [
        Self::Usvp,
        Self::Dsd,
        Self::Bdd,
        Self::BddHybrid,
        Self::BddMitmHybrid,
    ];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Optional user analysis settings before defaults and problem reductions resolve.
pub struct AnalysisSettings {
    pub security_model: SecurityModel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_model: Option<ReductionCostModel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduction_model: Option<ReductionModel>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Concrete cost and classical/quantum settings sent upstream.
pub struct ResolvedAnalysisSettings {
    pub security_model: SecurityModel,
    pub cost_model: ReductionCostModel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduction_model: Option<ReductionModel>,
}

impl Default for AnalysisSettings {
    fn default() -> Self {
        Self {
            security_model: SecurityModel::Classical,
            cost_model: None,
            reduction_model: None,
        }
    }
}

impl AnalysisSettings {
    /// Apply defaults and return the settings used for cache identity and execution.
    pub fn resolve(&self) -> ResolvedAnalysisSettings {
        let cost_model = self.cost_model.unwrap_or(match self.security_model {
            SecurityModel::Classical => ReductionCostModel::Bdgl16,
            SecurityModel::Quantum => ReductionCostModel::LaaMosPol14,
        });
        ResolvedAnalysisSettings {
            security_model: self.security_model,
            cost_model,
            reduction_model: self.reduction_model,
        }
    }
}

/// Return all attacks expected in the final report for a public problem.
pub fn attacks_for_problem(problem: &Problem) -> &'static [Attack] {
    match problem {
        Problem::Lwe(_) | Problem::Rlwe(_) | Problem::Glwe(_) => &Attack::LWE,
        Problem::Ntru(_) => &Attack::NTRU,
        Problem::Sis(_) => &[Attack::Lattice],
    }
}

/// Return attacks grouped into ordinary exact estimator requests.
pub fn fast_attacks_for_problem(problem: &Problem) -> &'static [Attack] {
    match problem {
        Problem::Lwe(_) | Problem::Rlwe(_) | Problem::Glwe(_) => &Attack::LWE_FAST,
        Problem::Ntru(_) => &Attack::NTRU,
        Problem::Sis(_) => &[Attack::Lattice],
    }
}

/// Return attacks that use dedicated preflight scheduling policy.
pub fn slow_attacks_for_problem(problem: &Problem) -> &'static [Attack] {
    match problem {
        Problem::Lwe(_) | Problem::Rlwe(_) | Problem::Glwe(_) => &Attack::LWE_SLOW,
        Problem::Ntru(_) | Problem::Sis(_) => &[],
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Scalar diagnostic value safe to persist and expose as JSON.
pub enum NormalizedMetric {
    Integer { value: SignedInteger },
    Decimal { value: ExactDecimal },
    Boolean { value: bool },
    Text { value: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
/// Whether a duration belongs to one attack or a shared Sage request group.
pub enum DurationScope {
    Attack,
    RequestGroup,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Measured execution duration and optional shared-attack ownership.
pub struct ExecutionTiming {
    pub duration_ms: u64,
    pub scope: DurationScope,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_attacks: Vec<Attack>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
/// Scheduling decision returned by a slow-attack preflight.
pub enum PreflightDecision {
    RunExact,
    SkipExact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
/// Arora-GB v6 search tier that completed the threshold decision.
pub enum PreflightPrecisionTier {
    Coarse,
    Refined,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Auditable preflight result retained alongside any later exact result.
pub enum PreflightTrace {
    ThresholdScreen {
        precision_tier: PreflightPrecisionTier,
        required_security_bits: ExactDecimal,
        requested_margin_bits: ExactDecimal,
        calibrated_margin_floor_bits: ExactDecimal,
        effective_margin_bits: ExactDecimal,
        threshold_bits: ExactDecimal,
        reason: String,
        timing: ExecutionTiming,
        #[serde(default)]
        metrics: BTreeMap<String, NormalizedMetric>,
        decision: PreflightDecision,
    },
    Computed {
        security_bits: ExactDecimal,
        timing: ExecutionTiming,
        #[serde(default)]
        metrics: BTreeMap<String, NormalizedMetric>,
        effective_margin_bits: ExactDecimal,
        threshold_bits: ExactDecimal,
        decision: PreflightDecision,
    },
    Unknown {
        code: String,
        reason: String,
        timing: ExecutionTiming,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        raw_result: Option<serde_json::Value>,
        decision: PreflightDecision,
    },
    Failed {
        code: String,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<ExecutionTiming>,
        decision: PreflightDecision,
    },
    NotRun {
        code: String,
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Wall-clock case execution interval excluding queue wait before first start.
pub struct CaseExecutionTiming {
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Stable final outcome of one attack in a security report.
pub enum AttackOutcome {
    Computed {
        security_bits: ExactDecimal,
        #[serde(default)]
        metrics: BTreeMap<String, NormalizedMetric>,
    },
    NoFiniteEstimate {
        code: String,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        raw_result: Option<serde_json::Value>,
    },
    Timeout {
        timeout_seconds: u64,
    },
    Failed {
        code: String,
        message: String,
        retryable: bool,
    },
    PolicySkipped {
        code: String,
        reason: String,
        applicability_rule_version: u32,
    },
    Skipped {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Exact transformation used to reduce a public problem to an estimator problem.
pub enum AnalysisModel {
    Direct {
        version: u32,
    },
    CoefficientEmbeddingV1 {
        version: u32,
        source_ring_samples: SampleCount,
        scalar_samples: SampleCount,
        derived_lwe: Box<LweProblem>,
        warnings: Vec<String>,
    },
}

/// Validate and reduce one public parameter case to the estimator API model.
pub fn analysis_model_for(
    problem: &Problem,
    settings: &AnalysisSettings,
) -> Result<AnalysisModel, ValidationError> {
    match problem {
        Problem::Lwe(_) | Problem::Ntru(_) | Problem::Sis(_) => {
            Ok(AnalysisModel::Direct { version: 1 })
        }
        Problem::Rlwe(problem) => {
            require_coefficient_embedding(settings)?;
            coefficient_embedding(
                &problem.negacyclic_ring,
                1,
                &problem.samples,
                &problem.secret,
                &problem.error,
            )
        }
        Problem::Glwe(problem) => {
            require_coefficient_embedding(settings)?;
            coefficient_embedding(
                &problem.negacyclic_ring,
                problem.dimension,
                &problem.samples,
                &problem.secret,
                &problem.error,
            )
        }
    }
}

fn require_coefficient_embedding(settings: &AnalysisSettings) -> Result<(), ValidationError> {
    if settings.reduction_model != Some(ReductionModel::CoefficientEmbeddingV1) {
        return Err(ValidationError::new(
            "analysis.reduction_model",
            "RLWE/GLWE requires an explicit coefficient_embedding_v1 reduction model",
        ));
    }
    Ok(())
}

fn coefficient_embedding(
    ring: &NegacyclicRing,
    glwe_dimension: u64,
    ring_samples: &SampleCount,
    secret: &SecretDistribution,
    error: &ErrorDistribution,
) -> Result<AnalysisModel, ValidationError> {
    let dimension = glwe_dimension
        .checked_mul(ring.polynomial_degree)
        .ok_or_else(|| ValidationError::new("problem", "derived scalar dimension overflows u64"))?;
    let scalar_samples = match ring_samples {
        SampleCount::Finite { count } => SampleCount::Finite {
            count: count.checked_mul(ring.polynomial_degree).ok_or_else(|| {
                ValidationError::new(
                    "problem.samples",
                    "derived scalar sample count overflows u64",
                )
            })?,
        },
        SampleCount::Unlimited => SampleCount::Unlimited,
    };
    Ok(AnalysisModel::CoefficientEmbeddingV1 {
        version: 1,
        source_ring_samples: ring_samples.clone(),
        scalar_samples: scalar_samples.clone(),
        derived_lwe: Box::new(LweProblem {
            dimension,
            modulus: ring.ciphertext_modulus.clone(),
            samples: scalar_samples,
            secret: secret.clone(),
            error: error.clone(),
        }),
        warnings: vec![
            "系数嵌入模型将带结构的系数方程视为无结构 LWE 实例".into(),
            "该结果不是对原始环问题的直接安全分析".into(),
        ],
    })
}
