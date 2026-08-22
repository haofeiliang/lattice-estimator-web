//! Deterministic serialization and hashing for attack-cache identities.
//!
//! Keys include normalized parameters, analysis settings, attack identity, and
//! estimator provenance; weakening this identity can return incorrect cached results.

use std::{collections::BTreeMap, fmt::Write};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    CANONICALIZATION_VERSION,
    domain::{AnalysisModel, Attack, EstimatorProblem, ResolvedAnalysisSettings},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Versions of the upstream estimator environment that produced a result.
pub struct EstimatorContext {
    pub estimator_commit: String,
    pub sage_version: String,
    pub adapter_version: String,
    pub worker_image: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Complete semantic identity of one exact attack result in the cache.
pub struct AttackCacheIdentity {
    pub canonicalization_version: u32,
    pub estimator_problem: EstimatorProblem,
    pub analysis_model: AnalysisModel,
    pub resolved_analysis: ResolvedAnalysisSettings,
    pub attack: Attack,
    pub estimator_context: EstimatorContext,
}

impl AttackCacheIdentity {
    /// Construct an identity from normalized problem and execution context.
    pub fn new(
        estimator_problem: EstimatorProblem,
        analysis_model: AnalysisModel,
        resolved_analysis: ResolvedAnalysisSettings,
        attack: Attack,
        estimator_context: EstimatorContext,
    ) -> Self {
        Self {
            canonicalization_version: CANONICALIZATION_VERSION,
            estimator_problem,
            analysis_model,
            resolved_analysis,
            attack,
            estimator_context,
        }
    }

    /// Return the stable SHA-256 key used by the database cache.
    pub fn hash(&self) -> String {
        stable_hash(self)
    }
}

/// Serialize recursively key-sorted JSON with no insignificant whitespace.
pub fn canonical_json<T: Serialize>(value: &T) -> String {
    let value = serde_json::to_value(value).expect("contract types serialize to JSON");
    serde_json::to_string(&canonicalize_value(value)).expect("canonical JSON value serializes")
}

/// Hash a value after canonical JSON serialization.
pub fn stable_hash<T: Serialize>(value: &T) -> String {
    let digest = Sha256::digest(canonical_json(value).as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("sha256:{encoded}")
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_value(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar,
    }
}
