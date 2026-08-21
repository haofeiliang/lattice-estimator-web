//! Pure domain model and rules.
//!
//! This module has no HTTP, database, process, or UI concerns. Consumers that
//! only need to read/write parameter sets and reports can depend on this
//! surface without knowing how the service executes work.

pub use crate::applicability::{
    ARORA_GB_PREFLIGHT_MARGIN_FLOOR_BITS, BKW_PREFLIGHT_MARGIN_FLOOR_BITS,
    SLOW_ATTACK_APPLICABILITY_RULE_VERSION, SlowAttackApplicability,
    reviewed_preflight_margin_floor, slow_attack_applicability,
};
pub use crate::canonical::{AttackCacheIdentity, EstimatorContext, canonical_json, stable_hash};
pub use crate::domain::*;
pub use crate::formats::*;
pub use crate::validation::{Validate, ValidationError};
