//! Versioned, deterministic applicability rules for expensive LWE attacks.

use num_bigint::BigInt;

use crate::{Attack, ErrorDistribution, EstimatorProblem, LweProblem};

/// Version of the reviewed slow-attack applicability rules.
pub const SLOW_ATTACK_APPLICABILITY_RULE_VERSION: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
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
        ErrorDistribution::DiscreteGaussian { standard_deviation } => {
            SlowAttackApplicability::applicable(
                "arora_gaussian_preflight",
                format!(
                    "Gaussian-like error with n={} and sigma={standard_deviation} is screened by the attack-specific Arora-GB estimate",
                    problem.dimension
                ),
            )
        }
        error => {
            let width = bounded_error_width(error)
                .expect("centered-binomial and uniform-integer errors are bounded");
            SlowAttackApplicability::applicable(
                "arora_bounded_exact",
                format!(
                    "bounded error support width D={width} and n={} use exact Arora-GB because the Gaussian preflight model does not apply",
                    problem.dimension
                ),
            )
        }
    }
}

fn bkw_applicability(problem: &LweProblem) -> SlowAttackApplicability {
    SlowAttackApplicability::applicable(
        "bkw_exact_enabled",
        format!(
            "n={} and q={} use exact BKW because the quick estimate is not calibrated for production skipping",
            problem.dimension, problem.modulus
        ),
    )
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
            "bkw_exact_enabled"
        );

        let outside = lwe(728, "2013265921", SampleCount::Unlimited, gaussian("11000"));
        assert_eq!(
            slow_attack_applicability(&outside, Attack::Bkw)
                .unwrap()
                .code,
            "bkw_exact_enabled"
        );
    }
}
