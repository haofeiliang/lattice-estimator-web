//! Versioned, deterministic applicability rules for expensive LWE attacks.

use bigdecimal::BigDecimal;
use num_bigint::BigInt;

use crate::{Attack, ErrorDistribution, EstimatorProblem, LweProblem};

/// Version of the reviewed slow-attack applicability rules.
pub const SLOW_ATTACK_APPLICABILITY_RULE_VERSION: u32 = 4;

/// Reviewed minimum margin for the quick Arora-GB coarse tier.
pub const ARORA_GB_COARSE_MARGIN_FLOOR_BITS: u64 = 64;
/// Reviewed minimum margin for the complete Arora-GB refined tier.
pub const ARORA_GB_REFINED_MARGIN_FLOOR_BITS: u64 = 10;
/// Reviewed minimum margin for numeric BKW preflight estimates.
pub const BKW_PREFLIGHT_MARGIN_FLOOR_BITS: u64 = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Whether a slow attack's parameter domain is approved for preflight skipping.
pub struct SlowAttackApplicability {
    pub code: &'static str,
    pub reason: String,
}

impl SlowAttackApplicability {
    fn applicable(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }
}

/// Classify a slow attack before deciding whether Sage needs to run it.
pub fn slow_attack_applicability(
    problem: &EstimatorProblem,
    attack: Attack,
) -> Option<SlowAttackApplicability> {
    let EstimatorProblem::Lwe(problem) = problem else {
        return None;
    };
    match attack {
        Attack::AroraGb => Some(arora_gb_applicability(problem)),
        Attack::Bkw => Some(bkw_applicability(problem)),
        _ => None,
    }
}

fn arora_gb_applicability(problem: &LweProblem) -> SlowAttackApplicability {
    match &problem.error {
        ErrorDistribution::DiscreteGaussian { standard_deviation }
            if reviewed_arora_gaussian(standard_deviation) =>
        {
            SlowAttackApplicability::applicable(
                "arora_gaussian_preflight",
                format!(
                    "高斯型噪声 n={}、sigma={standard_deviation} 使用 Arora-GB 专用快速估算筛选",
                    problem.dimension
                ),
            )
        }
        error if reviewed_bounded_error(error) => {
            let width = bounded_error_width(error)
                .expect("centered-binomial and uniform-integer errors are bounded");
            SlowAttackApplicability::applicable(
                "arora_bounded_preflight",
                format!(
                    "有界噪声支撑宽度 D={width}、n={} 使用经校准的 Arora-GB 快速估算筛选",
                    problem.dimension
                ),
            )
        }
        _ => SlowAttackApplicability::applicable(
            "arora_exact_unreviewed_error_model",
            format!(
                "n={} 的噪声分布不在 Arora-GB 快速估算审核域内，执行精确 Arora-GB",
                problem.dimension
            ),
        ),
    }
}

fn bkw_applicability(problem: &LweProblem) -> SlowAttackApplicability {
    match &problem.error {
        ErrorDistribution::DiscreteGaussian { standard_deviation } => {
            SlowAttackApplicability::applicable(
                "bkw_structural_preflight",
                format!(
                    "离散高斯噪声 n={}、q={}、sigma={standard_deviation} 使用结构化 coded-BKW 快速估算筛选",
                    problem.dimension, problem.modulus
                ),
            )
        }
        error if reviewed_bounded_error(error) => SlowAttackApplicability::applicable(
            "bkw_structural_bounded_preflight",
            format!(
                "n={}、q={} 的中心有界噪声使用经校准的结构化 coded-BKW 快速估算筛选",
                problem.dimension, problem.modulus
            ),
        ),
        _ => SlowAttackApplicability::applicable(
            "bkw_exact_unreviewed_error_model",
            format!(
                "n={}、q={} 的噪声模型尚未完成 BKW 快速估算校准，执行精确 BKW",
                problem.dimension, problem.modulus
            ),
        ),
    }
}

/// Return the per-attack uniform margin floor for a reviewed preflight domain.
pub fn reviewed_preflight_margin_floor(problem: &LweProblem, attack: Attack) -> Option<u64> {
    match attack {
        Attack::AroraGb if reviewed_arora_error(&problem.error) => {
            Some(ARORA_GB_REFINED_MARGIN_FLOOR_BITS)
        }
        Attack::Bkw if reviewed_bkw_error(&problem.error) => Some(BKW_PREFLIGHT_MARGIN_FLOOR_BITS),
        _ => None,
    }
}

fn reviewed_arora_error(error: &ErrorDistribution) -> bool {
    match error {
        ErrorDistribution::DiscreteGaussian { standard_deviation } => {
            reviewed_arora_gaussian(standard_deviation)
        }
        error => reviewed_bounded_error(error),
    }
}

fn reviewed_arora_gaussian(standard_deviation: &crate::ExactDecimal) -> bool {
    let sigma = standard_deviation.as_big_decimal();
    sigma >= BigDecimal::from(7) / BigDecimal::from(10) && sigma <= 4
}

fn reviewed_bkw_error(error: &ErrorDistribution) -> bool {
    matches!(error, ErrorDistribution::DiscreteGaussian { .. }) || reviewed_bounded_error(error)
}

fn reviewed_bounded_error(error: &ErrorDistribution) -> bool {
    match error {
        ErrorDistribution::CenteredBinomial { eta } => *eta <= 8,
        ErrorDistribution::UniformInteger { lower, upper } => {
            let lower = lower.as_bigint();
            let upper = upper.as_bigint();
            upper >= BigInt::from(1) && upper <= BigInt::from(8) && lower == -upper
        }
        ErrorDistribution::DiscreteGaussian { .. } => false,
    }
}

fn bounded_error_width(error: &ErrorDistribution) -> Option<BigInt> {
    match error {
        ErrorDistribution::CenteredBinomial { eta } => {
            Some(BigInt::from(*eta) * 2 + BigInt::from(1))
        }
        ErrorDistribution::UniformInteger { lower, upper } => {
            Some(upper.as_bigint() - lower.as_bigint() + BigInt::from(1))
        }
        ErrorDistribution::DiscreteGaussian { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExactDecimal, PositiveInteger, SampleCount, SecretDistribution};

    fn lwe(n: u64, q: &str, samples: SampleCount, error: ErrorDistribution) -> EstimatorProblem {
        EstimatorProblem::Lwe(LweProblem {
            dimension: n,
            modulus: PositiveInteger::new(q).unwrap(),
            samples,
            secret: SecretDistribution::UniformBinary,
            error,
        })
    }

    fn gaussian(value: &str) -> ErrorDistribution {
        ErrorDistribution::DiscreteGaussian {
            standard_deviation: ExactDecimal::new(value).unwrap(),
        }
    }

    #[test]
    fn finite_samples_remain_applicable_to_arora_gb() {
        let starved = lwe(
            128,
            "256",
            SampleCount::Finite { count: 16_384 },
            gaussian("1"),
        );
        assert_eq!(
            slow_attack_applicability(&starved, Attack::AroraGb)
                .unwrap()
                .code,
            "arora_gaussian_preflight"
        );

        let applicable = lwe(1024, "4096", SampleCount::Unlimited, gaussian("0.7"));
        assert_eq!(
            slow_attack_applicability(&applicable, Attack::AroraGb)
                .unwrap()
                .code,
            "arora_gaussian_preflight"
        );
    }

    #[test]
    fn bkw_remains_applicable_across_the_parameter_range() {
        let applicable = lwe(512, "4", SampleCount::Finite { count: 512 }, gaussian("1"));
        assert_eq!(
            slow_attack_applicability(&applicable, Attack::Bkw)
                .unwrap()
                .code,
            "bkw_structural_preflight"
        );

        let outside = lwe(728, "2013265921", SampleCount::Unlimited, gaussian("11000"));
        assert_eq!(
            slow_attack_applicability(&outside, Attack::Bkw)
                .unwrap()
                .code,
            "bkw_structural_preflight"
        );
    }

    #[test]
    fn only_calibrated_centered_bounded_errors_use_preflight() {
        let binomial = lwe(
            1024,
            "4096",
            SampleCount::Unlimited,
            ErrorDistribution::CenteredBinomial { eta: 8 },
        );
        assert_eq!(
            slow_attack_applicability(&binomial, Attack::AroraGb)
                .unwrap()
                .code,
            "arora_bounded_preflight"
        );
        assert_eq!(
            slow_attack_applicability(&binomial, Attack::Bkw)
                .unwrap()
                .code,
            "bkw_structural_bounded_preflight"
        );

        let finite_binomial = lwe(
            128,
            "4093",
            SampleCount::Finite { count: 4096 },
            ErrorDistribution::CenteredBinomial { eta: 8 },
        );
        assert_eq!(
            slow_attack_applicability(&finite_binomial, Attack::AroraGb)
                .unwrap()
                .code,
            "arora_bounded_preflight"
        );
        assert_eq!(
            slow_attack_applicability(&finite_binomial, Attack::Bkw)
                .unwrap()
                .code,
            "bkw_structural_bounded_preflight"
        );

        let unreviewed = lwe(
            1024,
            "4096",
            SampleCount::Unlimited,
            ErrorDistribution::UniformInteger {
                lower: crate::SignedInteger::new("0").unwrap(),
                upper: crate::SignedInteger::new("8").unwrap(),
            },
        );
        assert_eq!(
            slow_attack_applicability(&unreviewed, Attack::AroraGb)
                .unwrap()
                .code,
            "arora_exact_unreviewed_error_model"
        );
        assert_eq!(
            slow_attack_applicability(&unreviewed, Attack::Bkw)
                .unwrap()
                .code,
            "bkw_exact_unreviewed_error_model"
        );
    }
}
