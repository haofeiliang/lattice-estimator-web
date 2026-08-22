use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Weak},
    time::Duration,
};

use tokio::{
    sync::{Mutex, Notify, OwnedMutexGuard, Semaphore, mpsc},
    task::JoinSet,
};

use crate::{
    AnalysisModel, Attack, AttackCacheIdentity, AttackOutcome, AttackPreflight, AttackResult,
    CaseExecutionTiming, EstimateMode, EstimateRequest, EstimatorProblem, ExactDecimal,
    ExecutionTiming, NormalizedMetric, ParameterCase, PreflightDecision, PreflightPrecisionTier,
    PreflightTrace, Provenance, SLOW_ATTACK_APPLICABILITY_RULE_VERSION, SecurityReportEntry,
    SecurityReportFile, SecuritySummary, Validate, analysis_model_for, attacks_for_problem,
    canonical_json,
    database::{Database, JobWork},
    error::ServiceError,
    fast_attacks_for_problem,
    service::{BatchSnapshot, MAX_QUEUED_JOBS, RunState, now},
    slow_attack_applicability, slow_attacks_for_problem, stable_hash,
    upstream::{
        EstimatorClient, Metadata, WorkerAttackExecution, WorkerOutcome, WorkerPrecisionTier,
        WorkerRequest, WorkerThresholdDecision,
    },
};

pub struct Scheduler {
    receiver: mpsc::Receiver<String>,
    handle: SchedulerHandle,
    case_slots: Arc<Semaphore>,
}

#[derive(Clone)]
pub struct SchedulerHandle {
    sender: mpsc::Sender<String>,
    runner: Arc<Runner>,
    cancellation: Arc<Notify>,
}

struct Runner {
    database: Database,
    upstream: EstimatorClient,
    metadata: Metadata,
    estimator_slots: Arc<Semaphore>,
    single_flight: Mutex<HashMap<String, Weak<Mutex<()>>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkerControl {
    Completed,
    Cancelled,
    TimedOut,
}

struct PlanOptions {
    targets: Vec<Attack>,
    deadline: tokio::time::Instant,
}

struct PlanExecution {
    control: WorkerControl,
    results: BTreeMap<Attack, AttackResult>,
}

struct ProgressSnapshot<'a> {
    results: &'a BTreeMap<Attack, AttackResult>,
    preflights: &'a BTreeMap<Attack, PreflightTrace>,
}

impl Scheduler {
    pub fn new(
        database: Database,
        upstream: EstimatorClient,
        metadata: Metadata,
        case_concurrency: usize,
        estimator_concurrency: usize,
    ) -> (Self, SchedulerHandle) {
        let (sender, receiver) = mpsc::channel(MAX_QUEUED_JOBS);
        let runner = Arc::new(Runner {
            database,
            upstream,
            metadata,
            estimator_slots: Arc::new(Semaphore::new(estimator_concurrency)),
            single_flight: Mutex::new(HashMap::new()),
        });
        let handle = SchedulerHandle {
            sender,
            runner,
            cancellation: Arc::new(Notify::new()),
        };
        (
            Self {
                receiver,
                handle: handle.clone(),
                case_slots: Arc::new(Semaphore::new(case_concurrency)),
            },
            handle,
        )
    }

    pub async fn start(mut self) -> Result<(), ServiceError> {
        for job_id in self.handle.runner.database.queued_jobs().await? {
            self.handle.enqueue(job_id).await?;
        }
        tokio::spawn(async move {
            while let Some(job_id) = self.receiver.recv().await {
                let Ok(permit) = self.case_slots.clone().acquire_owned().await else {
                    break;
                };
                let handle = self.handle.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle.process(job_id).await {
                        tracing::error!(%error, "scheduler job failed");
                    }
                });
            }
        });
        Ok(())
    }
}

impl SchedulerHandle {
    pub async fn submit(
        &self,
        request: EstimateRequest,
        poll_after_seconds: u64,
    ) -> Result<(bool, BatchSnapshot), ServiceError> {
        request.validate()?;
        let fully_cached = self.runner.fully_cached(&request).await?;
        let mut batch = self.runner.database.create_batch(request).await?;
        batch.poll_after_seconds = poll_after_seconds;
        if fully_cached {
            for job_id in &batch.job_ids {
                self.process(job_id.clone()).await?;
            }
            return Ok((
                true,
                self.runner
                    .database
                    .batch(&batch.batch_id, poll_after_seconds)
                    .await?,
            ));
        }
        for job_id in &batch.job_ids {
            self.enqueue(job_id.clone()).await?;
        }
        Ok((false, batch))
    }

    pub async fn cancel(
        &self,
        batch_id: &str,
        poll_after_seconds: u64,
    ) -> Result<BatchSnapshot, ServiceError> {
        self.runner.database.request_cancel(batch_id).await?;
        self.cancellation.notify_waiters();
        self.runner.refresh_batch(batch_id).await?;
        self.runner
            .database
            .batch(batch_id, poll_after_seconds)
            .await
    }

    pub async fn force_exact_attack(
        &self,
        batch_id: &str,
        case_id: &str,
        attack: Attack,
        poll_after_seconds: u64,
    ) -> Result<BatchSnapshot, ServiceError> {
        if !matches!(attack, Attack::AroraGb | Attack::Bkw) {
            return Err(ServiceError::BadRequest(
                "only arora_gb and bkw support forced exact execution".to_owned(),
            ));
        }
        let (job_id, snapshot) = self
            .runner
            .database
            .queue_forced_attack(batch_id, case_id, attack, poll_after_seconds)
            .await?;
        if let Some(job_id) = job_id {
            self.enqueue(job_id).await?;
        }
        Ok(snapshot)
    }

    async fn enqueue(&self, job_id: String) -> Result<(), ServiceError> {
        self.sender
            .send(job_id)
            .await
            .map_err(|_| ServiceError::Internal("scheduler stopped".to_owned()))
    }

    async fn process(&self, job_id: String) -> Result<(), ServiceError> {
        let Some(work) = self.runner.database.claim_job(&job_id).await? else {
            return Ok(());
        };
        match self.runner.process_work(&work, &self.cancellation).await {
            Ok((state, report)) => {
                let requeued = self
                    .runner
                    .database
                    .finish_job(&job_id, state, report)
                    .await?;
                if requeued {
                    self.enqueue(job_id).await?;
                    return Ok(());
                }
            }
            Err(error) if matches!(error, ServiceError::Upstream(_)) && work.attempts < 2 => {
                self.runner
                    .database
                    .requeue_job(&job_id, &error.to_string())
                    .await?;
                self.enqueue(job_id.clone()).await?;
                return Ok(());
            }
            Err(error) => {
                let timestamp = now();
                let state = RunState::Failed {
                    finished_at: timestamp,
                    code: "estimation_failed".to_owned(),
                    message: error.to_string(),
                };
                let requeued = self
                    .runner
                    .database
                    .finish_job(&job_id, state, None)
                    .await?;
                if requeued {
                    self.enqueue(job_id).await?;
                    return Ok(());
                }
            }
        }
        self.runner.refresh_batch(&work.batch_id).await?;
        Ok(())
    }
}

impl Runner {
    async fn fully_cached(&self, request: &EstimateRequest) -> Result<bool, ServiceError> {
        for case in &request.cases {
            let context = self.case_context(case)?;
            for attack in fast_attacks_for_problem(&case.problem) {
                let key = context.cache_identity(*attack).hash();
                let Some(outcome) = self.database.cached_outcome(&key).await? else {
                    return Ok(false);
                };
                let _ = outcome;
            }
            if request.mode == EstimateMode::Rough {
                continue;
            }
            let policy = request.slow_attack_policy.as_ref().ok_or_else(|| {
                ServiceError::Internal("missing validated slow attack policy".to_owned())
            })?;
            let mut needs_preflight = Vec::new();
            for attack in slow_attacks_for_problem(&case.problem) {
                let key = context.cache_identity(*attack).hash();
                if self.database.cached_outcome(&key).await?.is_some() {
                    continue;
                }
                if policy.forces(*attack) {
                    return Ok(false);
                }
                if context.preflight_stop_margin(policy, *attack).is_none() {
                    return Ok(false);
                }
                needs_preflight.push(*attack);
            }
            if !needs_preflight.is_empty() {
                let mut preflight = WorkerRequest::new(
                    context.estimator_problem.clone(),
                    &context.resolved_analysis,
                    needs_preflight,
                    request.timeout_seconds.min(300),
                );
                preflight.required_security_bits = Some(policy.required_security_bits.clone());
                preflight.requested_arora_gb_coarse_margin_bits =
                    Some(policy.arora_gb_coarse_margin_bits.clone());
                preflight.requested_arora_gb_refined_margin_bits =
                    Some(policy.arora_gb_refined_margin_bits.clone());
                let response = match self.upstream.preflight(&preflight).await {
                    Ok(response) => response,
                    Err(_) => return Ok(false),
                };
                if response.results.into_iter().any(|result| {
                    let threshold = policy.required_security_bits.as_big_decimal()
                        + context
                            .preflight_stop_margin(policy, result.attack)
                            .expect("only calibrated attacks are sent to preflight");
                    match (&result.attack, &result.outcome) {
                        (
                            Attack::AroraGb,
                            WorkerOutcome::ThresholdScreen {
                                decision: WorkerThresholdDecision::AboveThreshold,
                                precision_tier,
                                required_security_bits,
                                requested_margin_bits,
                                calibrated_margin_floor_bits,
                                effective_margin_bits,
                                decision_threshold_bits,
                                metrics,
                                ..
                            },
                        ) => {
                            !arora_v6_rule_is_reviewed(metrics)
                                || required_security_bits != &policy.required_security_bits
                                || requested_margin_bits
                                    != arora_requested_margin(policy, *precision_tier)
                                || !arora_v6_policy_fields_are_reviewed(
                                    *precision_tier,
                                    required_security_bits,
                                    requested_margin_bits,
                                    calibrated_margin_floor_bits,
                                    effective_margin_bits,
                                    decision_threshold_bits,
                                )
                        }
                        (Attack::Bkw, outcome) => reviewed_preflight_security_bits(outcome)
                            .is_none_or(|security_bits| security_bits.as_big_decimal() < threshold),
                        _ => true,
                    }
                }) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    async fn process_work(
        self: &Arc<Self>,
        work: &JobWork,
        cancellation: &Arc<Notify>,
    ) -> Result<(RunState, Option<SecurityReportEntry>), ServiceError> {
        let context = self.case_context(&work.case)?;
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(work.request.timeout_seconds);
        let mut results = work
            .prior_result
            .iter()
            .flat_map(|entry| &entry.attacks)
            .filter(|result| {
                !work.forced_attack_overrides.contains(&result.attack)
                    && matches!(
                        result.outcome,
                        AttackOutcome::Computed { .. }
                            | AttackOutcome::NoFiniteEstimate { .. }
                            | AttackOutcome::PolicySkipped { .. }
                    )
            })
            .map(|result| (result.attack, result.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut preflights = work
            .prior_result
            .iter()
            .flat_map(|entry| &entry.preflights)
            .map(|preflight| (preflight.attack, preflight.trace.clone()))
            .collect::<BTreeMap<_, _>>();
        for attack in attacks_for_problem(&work.case.problem) {
            let key = context.cache_identity(*attack).hash();
            if let Some(cached) = self.database.cached_outcome(&key).await? {
                results.entry(*attack).or_insert_with(|| AttackResult {
                    attack: *attack,
                    cached: true,
                    timing: cached.timing,
                    outcome: cached.outcome,
                });
                if slow_attacks_for_problem(&work.case.problem).contains(attack) {
                    preflights
                        .entry(*attack)
                        .or_insert_with(|| PreflightTrace::NotRun {
                            code: "exact_cache_hit".to_owned(),
                            reason: "命中精确攻击缓存，因此未执行快速估算".to_owned(),
                        });
                }
            }
        }
        self.publish_progress(work, &context, &results, &preflights, false)
            .await?;

        let fast_plans = fast_attack_groups(&work.case.problem, &results);
        let mut fast_estimate = false;
        if !fast_plans.is_empty() {
            let execution = self
                .run_plans(
                    work,
                    &context,
                    fast_plans,
                    deadline,
                    cancellation,
                    ProgressSnapshot {
                        results: &results,
                        preflights: &preflights,
                    },
                )
                .await?;
            results.extend(execution.results);
            match execution.control {
                WorkerControl::Cancelled => {
                    return Ok(self.cancelled_completion(work, &context, results, preflights));
                }
                WorkerControl::TimedOut => {
                    return Ok(self.timed_out_completion(work, &context, results, preflights));
                }
                WorkerControl::Completed => {}
            }
        }

        let missing_slow = slow_attacks_for_problem(&work.case.problem)
            .iter()
            .copied()
            .filter(|attack| !results.contains_key(attack))
            .collect::<Vec<_>>();

        let control = if work.request.mode == EstimateMode::Rough {
            for attack in missing_slow {
                preflights.insert(
                    attack,
                    PreflightTrace::NotRun {
                        code: "rough_mode".to_owned(),
                        reason: "快速模式不执行慢攻击快速筛选".to_owned(),
                    },
                );
                results.entry(attack).or_insert_with(|| AttackResult {
                    attack,
                    cached: false,
                    timing: None,
                    outcome: AttackOutcome::Skipped {
                        reason: "rough mode runs fast attacks only".to_owned(),
                    },
                });
            }
            fast_estimate = true;
            WorkerControl::Completed
        } else {
            let policy = work.request.slow_attack_policy.as_ref().ok_or_else(|| {
                ServiceError::Internal("missing validated slow attack policy".to_owned())
            })?;
            let (forced, automatic): (Vec<_>, Vec<_>) = missing_slow
                .into_iter()
                .partition(|attack| policy.forces(*attack));
            let mut slow_candidates = forced;
            for attack in &slow_candidates {
                preflights
                    .entry(*attack)
                    .or_insert_with(|| PreflightTrace::NotRun {
                        code: "forced_exact".to_owned(),
                        reason: "用户要求运行精确攻击，已绕过快速估算".to_owned(),
                    });
            }
            slow_candidates.extend(
                self.apply_preflight_skips(
                    work,
                    &context,
                    automatic,
                    policy,
                    &mut results,
                    &mut preflights,
                )
                .await?,
            );
            if slow_candidates.is_empty() {
                self.publish_progress(work, &context, &results, &preflights, false)
                    .await?;
                WorkerControl::Completed
            } else {
                self.publish_progress(work, &context, &results, &preflights, false)
                    .await?;
                let plans = slow_candidates
                    .into_iter()
                    .map(|attack| vec![attack])
                    .collect();
                let execution = self
                    .run_plans(
                        work,
                        &context,
                        plans,
                        deadline,
                        cancellation,
                        ProgressSnapshot {
                            results: &results,
                            preflights: &preflights,
                        },
                    )
                    .await?;
                results.extend(execution.results);
                execution.control
            }
        };

        match control {
            WorkerControl::Cancelled => {
                return Ok(self.cancelled_completion(work, &context, results, preflights));
            }
            WorkerControl::TimedOut => {
                return Ok(self.timed_out_completion(work, &context, results, preflights));
            }
            WorkerControl::Completed => {}
        }

        let finished_at = now();
        let entry = self.report_entry(
            work,
            &context,
            results,
            preflights,
            fast_estimate,
            Some(finished_at.clone()),
        );
        let state = if entry.summary.complete {
            RunState::Completed { finished_at }
        } else {
            RunState::Partial { finished_at }
        };
        Ok((state, Some(entry)))
    }

    async fn run_plans(
        self: &Arc<Self>,
        work: &JobWork,
        context: &CaseContext,
        plans: Vec<Vec<Attack>>,
        deadline: tokio::time::Instant,
        cancellation: &Arc<Notify>,
        progress_snapshot: ProgressSnapshot<'_>,
    ) -> Result<PlanExecution, ServiceError> {
        let mut tasks = JoinSet::new();
        for targets in plans {
            let plan_targets = targets.clone();
            let runner = Arc::clone(self);
            let work = work.clone();
            let context = context.clone();
            let cancellation = Arc::clone(cancellation);
            tasks.spawn(async move {
                let execution = runner
                    .run_plan(
                        &work,
                        &context,
                        PlanOptions { targets, deadline },
                        &cancellation,
                    )
                    .await;
                (plan_targets, execution)
            });
        }

        let mut control = WorkerControl::Completed;
        let mut results = BTreeMap::new();
        while let Some(joined) = tasks.join_next().await {
            let execution = match joined {
                Ok((_, Ok(execution))) => execution,
                Ok((targets, Err(error)))
                    if matches!(error, ServiceError::Upstream(_)) && work.attempts >= 2 =>
                {
                    tracing::warn!(
                        %error,
                        attacks = ?targets,
                        "estimator plan failed after retry"
                    );
                    let mut failures = BTreeMap::new();
                    insert_plan_failures(&targets, &error, &mut failures);
                    PlanExecution {
                        control: WorkerControl::Completed,
                        results: failures,
                    }
                }
                Ok((_, Err(error))) => {
                    tasks.shutdown().await;
                    return Err(error);
                }
                Err(error) => {
                    tasks.shutdown().await;
                    return Err(ServiceError::Internal(format!(
                        "estimator plan task failed: {error}"
                    )));
                }
            };
            results.extend(execution.results);
            let mut progress = progress_snapshot.results.clone();
            progress.extend(results.clone());
            self.publish_progress(
                work,
                context,
                &progress,
                progress_snapshot.preflights,
                false,
            )
            .await?;
            control = match (control, execution.control) {
                (WorkerControl::Cancelled, _) | (_, WorkerControl::Cancelled) => {
                    WorkerControl::Cancelled
                }
                (WorkerControl::TimedOut, _) | (_, WorkerControl::TimedOut) => {
                    WorkerControl::TimedOut
                }
                _ => WorkerControl::Completed,
            };
        }
        Ok(PlanExecution { control, results })
    }

    async fn publish_progress(
        &self,
        work: &JobWork,
        context: &CaseContext,
        results: &BTreeMap<Attack, AttackResult>,
        preflights: &BTreeMap<Attack, PreflightTrace>,
        fast_estimate: bool,
    ) -> Result<(), ServiceError> {
        if results.is_empty() && preflights.is_empty() {
            return Ok(());
        }
        let entry = self.report_entry(
            work,
            context,
            results.clone(),
            preflights.clone(),
            fast_estimate,
            None,
        );
        self.database.publish_job_result(&work.job_id, &entry).await
    }

    async fn apply_preflight_skips(
        &self,
        work: &JobWork,
        context: &CaseContext,
        attacks: Vec<Attack>,
        policy: &crate::SlowAttackPolicy,
        results: &mut BTreeMap<Attack, AttackResult>,
        preflights: &mut BTreeMap<Attack, PreflightTrace>,
    ) -> Result<Vec<Attack>, ServiceError> {
        let (preflight_attacks, mut candidates): (Vec<_>, Vec<_>) = attacks
            .into_iter()
            .partition(|attack| context.preflight_stop_margin(policy, *attack).is_some());
        for attack in &candidates {
            let reason = context
                .applicability(*attack)
                .map(|value| value.reason)
                .unwrap_or_else(|_| "参数不在快速估算审核域".to_owned());
            preflights.insert(
                *attack,
                PreflightTrace::NotRun {
                    code: "unreviewed_domain".to_owned(),
                    reason,
                },
            );
        }
        if preflight_attacks.is_empty() {
            return Ok(candidates);
        }
        let mut request = WorkerRequest::new(
            context.estimator_problem.clone(),
            &context.resolved_analysis,
            preflight_attacks.clone(),
            work.request.timeout_seconds.min(300),
        );
        request.required_security_bits = Some(policy.required_security_bits.clone());
        request.requested_arora_gb_coarse_margin_bits =
            Some(policy.arora_gb_coarse_margin_bits.clone());
        request.requested_arora_gb_refined_margin_bits =
            Some(policy.arora_gb_refined_margin_bits.clone());
        let response = match self.upstream.preflight(&request).await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(%error, "slow-attack preflight failed; running attacks conservatively");
                for attack in &preflight_attacks {
                    preflights.insert(
                        *attack,
                        PreflightTrace::Failed {
                            code: "preflight_request_failed".to_owned(),
                            message: error.to_string(),
                            timing: None,
                            decision: PreflightDecision::RunExact,
                        },
                    );
                }
                candidates.extend(preflight_attacks);
                return Ok(candidates);
            }
        };
        let mut returned = Vec::new();
        for execution in response.results {
            returned.push(execution.attack);
            let effective_margin = context
                .preflight_stop_margin(policy, execution.attack)
                .expect("only calibrated attacks are sent to preflight");
            let threshold = policy.required_security_bits.as_big_decimal() + &effective_margin;
            let effective_margin_bits = ExactDecimal::new(effective_margin.to_string())
                .expect("validated margin remains a canonical decimal");
            let threshold_bits = ExactDecimal::new(threshold.to_string())
                .expect("validated threshold remains a canonical decimal");
            let timing = worker_timing(&execution, None);
            match execution.outcome {
                WorkerOutcome::ThresholdScreen {
                    decision,
                    precision_tier,
                    required_security_bits,
                    requested_margin_bits,
                    calibrated_margin_floor_bits,
                    effective_margin_bits,
                    decision_threshold_bits,
                    reason,
                    metrics,
                } if execution.attack == Attack::AroraGb
                    && arora_v6_rule_is_reviewed(&metrics)
                    && required_security_bits == policy.required_security_bits
                    && &requested_margin_bits == arora_requested_margin(policy, precision_tier)
                    && arora_v6_policy_fields_are_reviewed(
                        precision_tier,
                        &required_security_bits,
                        &requested_margin_bits,
                        &calibrated_margin_floor_bits,
                        &effective_margin_bits,
                        &decision_threshold_bits,
                    ) =>
                {
                    let skip = decision == WorkerThresholdDecision::AboveThreshold;
                    preflights.insert(
                        execution.attack,
                        PreflightTrace::ThresholdScreen {
                            precision_tier: match precision_tier {
                                WorkerPrecisionTier::Coarse => PreflightPrecisionTier::Coarse,
                                WorkerPrecisionTier::Refined => PreflightPrecisionTier::Refined,
                            },
                            required_security_bits,
                            requested_margin_bits,
                            calibrated_margin_floor_bits,
                            effective_margin_bits,
                            threshold_bits: decision_threshold_bits.clone(),
                            reason: reason.clone(),
                            timing,
                            metrics,
                            decision: if skip {
                                PreflightDecision::SkipExact
                            } else {
                                PreflightDecision::RunExact
                            },
                        },
                    );
                    if skip {
                        results.insert(
                            execution.attack,
                            AttackResult {
                                attack: execution.attack,
                                cached: false,
                                timing: None,
                                outcome: AttackOutcome::PolicySkipped {
                                    code: "attack_preflight_above_threshold".to_owned(),
                                    reason: format!(
                                        "Arora-GB v6 target screen confirmed security above {decision_threshold_bits} bits"
                                    ),
                                    applicability_rule_version:
                                        SLOW_ATTACK_APPLICABILITY_RULE_VERSION,
                                },
                            },
                        );
                    } else {
                        candidates.push(execution.attack);
                    }
                }
                WorkerOutcome::ThresholdScreen { .. } => {
                    preflights.insert(
                        execution.attack,
                        PreflightTrace::Failed {
                            code: "unreviewed_threshold_screen".to_owned(),
                            message:
                                "Arora-GB 快速筛选目标、余量或规则版本不匹配，保守回退精确计算"
                                    .to_owned(),
                            timing: Some(timing),
                            decision: PreflightDecision::RunExact,
                        },
                    );
                    candidates.push(execution.attack);
                }
                WorkerOutcome::Computed {
                    security_bits,
                    metrics,
                } if execution.attack == Attack::Bkw && bkw_v5_rule_is_reviewed(&metrics) => {
                    let skip = security_bits.as_big_decimal() >= threshold;
                    preflights.insert(
                        execution.attack,
                        PreflightTrace::Computed {
                            security_bits: security_bits.clone(),
                            timing,
                            metrics,
                            effective_margin_bits,
                            threshold_bits,
                            decision: if skip {
                                PreflightDecision::SkipExact
                            } else {
                                PreflightDecision::RunExact
                            },
                        },
                    );
                    if skip {
                        results.insert(
                            execution.attack,
                            AttackResult {
                                attack: execution.attack,
                                cached: false,
                                timing: None,
                                outcome: AttackOutcome::PolicySkipped {
                                    code: "attack_preflight_above_threshold".to_owned(),
                                    reason: format!(
                                        "{} preflight estimate {} bits is at least the required security plus the effective {}-bit margin",
                                        slow_attack_label(execution.attack),
                                        security_bits,
                                        effective_margin
                                    ),
                                    applicability_rule_version: SLOW_ATTACK_APPLICABILITY_RULE_VERSION,
                                },
                            },
                        );
                    } else {
                        candidates.push(execution.attack);
                    }
                }
                WorkerOutcome::Computed { .. } => {
                    preflights.insert(
                        execution.attack,
                        PreflightTrace::Failed {
                            code: "unreviewed_preflight_rule".to_owned(),
                            message: "快速估算规则版本未通过审核，保守回退精确计算".to_owned(),
                            timing: Some(timing),
                            decision: PreflightDecision::RunExact,
                        },
                    );
                    candidates.push(execution.attack);
                }
                WorkerOutcome::PreflightUnknown {
                    code,
                    reason,
                    raw_result,
                }
                | WorkerOutcome::NoFiniteEstimate {
                    code,
                    reason,
                    raw_result,
                } => {
                    preflights.insert(
                        execution.attack,
                        PreflightTrace::Unknown {
                            code,
                            reason,
                            timing,
                            raw_result,
                            decision: PreflightDecision::RunExact,
                        },
                    );
                    candidates.push(execution.attack);
                }
                WorkerOutcome::Unsupported { code, reason } => {
                    preflights.insert(
                        execution.attack,
                        PreflightTrace::Failed {
                            code,
                            message: reason,
                            timing: Some(timing),
                            decision: PreflightDecision::RunExact,
                        },
                    );
                    candidates.push(execution.attack);
                }
                WorkerOutcome::Failed { code, message, .. } => {
                    preflights.insert(
                        execution.attack,
                        PreflightTrace::Failed {
                            code,
                            message,
                            timing: Some(timing),
                            decision: PreflightDecision::RunExact,
                        },
                    );
                    candidates.push(execution.attack);
                }
            }
        }
        for attack in preflight_attacks {
            if !returned.contains(&attack) {
                preflights.insert(
                    attack,
                    PreflightTrace::Failed {
                        code: "missing_preflight_result".to_owned(),
                        message: "快速估算响应缺少该攻击结果，保守回退精确计算".to_owned(),
                        timing: None,
                        decision: PreflightDecision::RunExact,
                    },
                );
                candidates.push(attack);
            }
        }
        Ok(candidates)
    }

    async fn acquire_flight_locks(
        &self,
        work: &JobWork,
        context: &CaseContext,
        targets: &[Attack],
        deadline: tokio::time::Instant,
        cancellation: &Notify,
    ) -> Result<Vec<OwnedMutexGuard<()>>, WorkerControl> {
        let mut keyed_locks = {
            let mut in_flight = self.single_flight.lock().await;
            in_flight.retain(|_, lock| lock.strong_count() > 0);
            targets
                .iter()
                .map(|attack| {
                    let key = context.cache_identity(*attack).hash();
                    let lock = in_flight
                        .get(&key)
                        .and_then(Weak::upgrade)
                        .unwrap_or_else(|| {
                            let lock = Arc::new(Mutex::new(()));
                            in_flight.insert(key.clone(), Arc::downgrade(&lock));
                            lock
                        });
                    (key, lock)
                })
                .collect::<Vec<_>>()
        };
        keyed_locks.sort_by(|left, right| left.0.cmp(&right.0));

        let mut guards = Vec::with_capacity(keyed_locks.len());
        for (_, lock) in keyed_locks {
            let acquire = lock.lock_owned();
            tokio::pin!(acquire);
            let cancel =
                wait_for_cancel(&self.database, &work.batch_id, &work.job_id, cancellation);
            tokio::pin!(cancel);
            let guard = tokio::select! {
                biased;
                guard = &mut acquire => guard,
                () = tokio::time::sleep_until(deadline) => {
                    return Err(WorkerControl::TimedOut);
                }
                () = &mut cancel => return Err(WorkerControl::Cancelled),
            };
            guards.push(guard);
        }
        Ok(guards)
    }

    async fn run_plan(
        &self,
        work: &JobWork,
        context: &CaseContext,
        options: PlanOptions,
        cancellation: &Notify,
    ) -> Result<PlanExecution, ServiceError> {
        let PlanOptions {
            mut targets,
            deadline,
        } = options;
        let mut results = BTreeMap::new();
        if deadline <= tokio::time::Instant::now() {
            insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
            return Ok(PlanExecution {
                control: WorkerControl::TimedOut,
                results,
            });
        }

        let _flight_guards = match self
            .acquire_flight_locks(work, context, &targets, deadline, cancellation)
            .await
        {
            Ok(guards) => guards,
            Err(control) => {
                if control == WorkerControl::TimedOut {
                    insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
                }
                return Ok(PlanExecution { control, results });
            }
        };

        for attack in &targets {
            let key = context.cache_identity(*attack).hash();
            if let Some(cached) = self.database.cached_outcome(&key).await? {
                results.insert(
                    *attack,
                    AttackResult {
                        attack: *attack,
                        cached: true,
                        timing: cached.timing,
                        outcome: cached.outcome,
                    },
                );
            }
        }
        targets.retain(|attack| !results.contains_key(attack));
        if targets.is_empty() {
            return Ok(PlanExecution {
                control: WorkerControl::Completed,
                results,
            });
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
            return Ok(PlanExecution {
                control: WorkerControl::TimedOut,
                results,
            });
        }

        let slot = self.estimator_slots.clone().acquire_owned();
        tokio::pin!(slot);
        let cancel = wait_for_cancel(&self.database, &work.batch_id, &work.job_id, cancellation);
        tokio::pin!(cancel);
        let _slot = tokio::select! {
            biased;
            slot = &mut slot => slot.map_err(|_| {
                ServiceError::Internal("estimator concurrency limiter closed".to_owned())
            })?,
            () = tokio::time::sleep_until(deadline) => {
                insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
                return Ok(PlanExecution {
                    control: WorkerControl::TimedOut,
                    results,
                });
            }
            () = &mut cancel => {
                return Ok(PlanExecution {
                    control: WorkerControl::Cancelled,
                    results,
                });
            }
        };

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let worker_timeout = remaining.as_secs().max(1).min(work.request.timeout_seconds);
        let request = WorkerRequest::new(
            context.estimator_problem.clone(),
            &context.resolved_analysis,
            targets.clone(),
            worker_timeout,
        );
        let worker = self.upstream.estimate(&request);
        tokio::pin!(worker);
        let cancel = wait_for_cancel(&self.database, &work.batch_id, &work.job_id, cancellation);
        tokio::pin!(cancel);

        let response = tokio::select! {
            biased;
            response = &mut worker => response,
            () = tokio::time::sleep_until(deadline) => {
                insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
                return Ok(PlanExecution {
                    control: WorkerControl::TimedOut,
                    results,
                });
            }
            () = &mut cancel => {
                return Ok(PlanExecution {
                    control: WorkerControl::Cancelled,
                    results,
                });
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(ServiceError::UpstreamTimeout(_)) => {
                insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
                return Ok(PlanExecution {
                    control: WorkerControl::TimedOut,
                    results,
                });
            }
            Err(error) => return Err(error),
        };
        if response.provenance.estimator_commit != self.metadata.estimator_commit
            || response.provenance.sage_version != self.metadata.sage_version
            || response.provenance.adapter_version != self.metadata.adapter_version
            || response.provenance.worker_image != self.metadata.worker_image
        {
            return Err(ServiceError::Upstream(
                "worker provenance changed after metadata discovery".to_owned(),
            ));
        }

        let mut retryable_failure = false;
        for execution in response.results {
            if !targets.contains(&execution.attack) {
                continue;
            }
            let timing = Some(worker_timing(&execution, Some(response.duration_ms)));
            let outcome = match execution.outcome {
                WorkerOutcome::Computed {
                    security_bits,
                    metrics,
                } => AttackOutcome::Computed {
                    security_bits,
                    metrics,
                },
                WorkerOutcome::NoFiniteEstimate {
                    code,
                    reason,
                    raw_result,
                } => AttackOutcome::NoFiniteEstimate {
                    code,
                    reason,
                    raw_result,
                },
                WorkerOutcome::PreflightUnknown { code, reason, .. } => AttackOutcome::Failed {
                    code: format!("unexpected_preflight_outcome:{code}"),
                    message: format!("exact estimator returned a preflight-only outcome: {reason}"),
                    retryable: false,
                },
                WorkerOutcome::ThresholdScreen { reason, .. } => AttackOutcome::Failed {
                    code: "unexpected_threshold_screen".to_owned(),
                    message: format!(
                        "exact estimator returned a preflight-only threshold screen: {reason}"
                    ),
                    retryable: false,
                },
                WorkerOutcome::Unsupported { code, reason } => {
                    AttackOutcome::Unsupported { code, reason }
                }
                WorkerOutcome::Failed {
                    code,
                    message,
                    retryable,
                } => {
                    retryable_failure |= retryable;
                    AttackOutcome::Failed {
                        code,
                        message,
                        retryable,
                    }
                }
            };
            if matches!(
                outcome,
                AttackOutcome::Computed { .. } | AttackOutcome::NoFiniteEstimate { .. }
            ) {
                let identity = context.cache_identity(execution.attack);
                self.database
                    .put_cached_outcome(
                        identity.hash(),
                        execution.attack,
                        outcome.clone(),
                        timing.clone(),
                        canonical_json(&self.metadata.context()),
                    )
                    .await?;
            }
            results.insert(
                execution.attack,
                AttackResult {
                    attack: execution.attack,
                    cached: false,
                    timing,
                    outcome,
                },
            );
        }
        for attack in targets {
            results.entry(attack).or_insert_with(|| AttackResult {
                attack,
                cached: false,
                timing: None,
                outcome: AttackOutcome::Failed {
                    code: "missing_worker_result".to_owned(),
                    message: "worker omitted a target result".to_owned(),
                    retryable: false,
                },
            });
        }
        if retryable_failure && work.attempts < 2 {
            return Err(ServiceError::Upstream(
                "worker reported a retryable attack failure".to_owned(),
            ));
        }
        Ok(PlanExecution {
            control: WorkerControl::Completed,
            results,
        })
    }

    fn cancelled_completion(
        &self,
        work: &JobWork,
        context: &CaseContext,
        results: BTreeMap<Attack, AttackResult>,
        preflights: BTreeMap<Attack, PreflightTrace>,
    ) -> (RunState, Option<SecurityReportEntry>) {
        let timestamp = now();
        if results.is_empty() && preflights.is_empty() {
            return (
                RunState::Cancelled {
                    finished_at: timestamp,
                },
                None,
            );
        }
        let entry = self.report_entry(
            work,
            context,
            results,
            preflights,
            false,
            Some(timestamp.clone()),
        );
        (
            RunState::Partial {
                finished_at: timestamp,
            },
            Some(entry),
        )
    }

    fn timed_out_completion(
        &self,
        work: &JobWork,
        context: &CaseContext,
        results: BTreeMap<Attack, AttackResult>,
        preflights: BTreeMap<Attack, PreflightTrace>,
    ) -> (RunState, Option<SecurityReportEntry>) {
        let finished_at = now();
        let entry = self.report_entry(
            work,
            context,
            results,
            preflights,
            false,
            Some(finished_at.clone()),
        );
        (RunState::TimedOut { finished_at }, Some(entry))
    }

    fn report_entry(
        &self,
        work: &JobWork,
        context: &CaseContext,
        results: BTreeMap<Attack, AttackResult>,
        preflights: BTreeMap<Attack, PreflightTrace>,
        fast_estimate: bool,
        finished_at: Option<String>,
    ) -> SecurityReportEntry {
        let ordered = attacks_for_problem(&work.case.problem)
            .iter()
            .filter_map(|attack| results.get(attack).cloned())
            .collect::<Vec<_>>();
        let estimates = ordered.iter().filter_map(|result| match &result.outcome {
            AttackOutcome::Computed { security_bits, .. } => Some((result.attack, security_bits)),
            _ => None,
        });
        let best =
            estimates.min_by(|left, right| left.1.as_big_decimal().cmp(&right.1.as_big_decimal()));
        let threshold_skipped = ordered.iter().any(|result| {
            matches!(
                &result.outcome,
                AttackOutcome::PolicySkipped { code, .. }
                    if code == "attack_preflight_above_threshold"
            )
        });
        let complete = work.request.mode == EstimateMode::Normal
            && ordered.len() == attacks_for_problem(&work.case.problem).len()
            && ordered.iter().all(|result| {
                matches!(
                    result.outcome,
                    AttackOutcome::Computed { .. }
                        | AttackOutcome::NoFiniteEstimate { .. }
                        | AttackOutcome::PolicySkipped { .. }
                )
            });
        let request_hash = stable_hash(&(
            SLOW_ATTACK_APPLICABILITY_RULE_VERSION,
            work.request.mode,
            &work.request.slow_attack_policy,
            attacks_for_problem(&work.case.problem)
                .iter()
                .map(|attack| context.cache_identity(*attack))
                .collect::<Vec<_>>(),
        ));
        let mut warnings = analysis_warnings(&context.analysis_model);
        if threshold_skipped {
            warnings.push(
                "慢攻击的专用快速估算已达到目标安全值与余量，因此跳过精确计算；完整性以该快速筛选策略为准"
                    .to_owned(),
            );
        }
        if let Some(policy) = &work.request.slow_attack_policy
            && !policy.forced_attacks.is_empty()
        {
            let attacks = policy
                .forced_attacks
                .iter()
                .map(|attack| slow_attack_label(*attack))
                .collect::<Vec<_>>()
                .join(", ");
            warnings.push(format!(
                "已手动强制运行慢攻击（{attacks}），未采用快速筛选的停止规则"
            ));
            for attack in &policy.forced_attacks {
                let applicability = context
                    .applicability(*attack)
                    .expect("forced slow attacks have applicability rules");
                warnings.push(format!(
                    "{} 策略记录：{} — {}",
                    slow_attack_label(*attack),
                    applicability.code,
                    applicability.reason
                ));
            }
        }
        SecurityReportEntry {
            case: work.case.clone(),
            execution: CaseExecutionTiming {
                started_at: work.started_at.clone(),
                finished_at,
            },
            request_hash,
            provenance: Provenance {
                estimator_commit: self.metadata.estimator_commit.clone(),
                sage_version: self.metadata.sage_version.clone(),
                adapter_version: self.metadata.adapter_version.clone(),
                worker_image: self.metadata.worker_image.clone(),
                analysis_model: context.analysis_model.clone(),
                resolved_analysis: context.resolved_analysis.clone(),
                created_at: now(),
            },
            summary: SecuritySummary {
                security_bits: best.map(|(_, bits)| bits.clone()),
                best_attack: best.map(|(attack, _)| attack),
                complete,
                fast_estimate,
                warnings,
            },
            preflights: slow_attacks_for_problem(&work.case.problem)
                .iter()
                .filter_map(|attack| {
                    preflights
                        .get(attack)
                        .cloned()
                        .map(|trace| AttackPreflight {
                            attack: *attack,
                            trace,
                        })
                })
                .collect(),
            attacks: ordered,
        }
    }

    fn case_context(&self, case: &ParameterCase) -> Result<CaseContext, ServiceError> {
        let analysis_model = analysis_model_for(&case.problem, &case.analysis)?;
        let estimator_problem = match (&case.problem, &analysis_model) {
            (crate::Problem::Lwe(problem), _) => EstimatorProblem::Lwe(problem.clone()),
            (crate::Problem::Ntru(problem), _) => EstimatorProblem::Ntru(problem.clone()),
            (crate::Problem::Sis(problem), _) => EstimatorProblem::Sis(problem.clone()),
            (_, AnalysisModel::CoefficientEmbeddingV1 { derived_lwe, .. }) => {
                EstimatorProblem::Lwe((**derived_lwe).clone())
            }
            _ => {
                return Err(ServiceError::Internal(
                    "problem and analysis model disagree".to_owned(),
                ));
            }
        };
        Ok(CaseContext {
            estimator_problem,
            analysis_model,
            resolved_analysis: case.analysis.resolve(),
            estimator_context: self.metadata.context(),
        })
    }

    async fn refresh_batch(&self, batch_id: &str) -> Result<(), ServiceError> {
        let batch = self.database.batch(batch_id, 1).await?;
        let request = self.database.batch_request(batch_id).await?;
        let mut states = Vec::with_capacity(batch.job_ids.len());
        for job_id in &batch.job_ids {
            states.push(self.database.job(job_id).await?.state);
        }
        if states
            .iter()
            .any(|state| !state.terminal() && !matches!(state, RunState::Interrupted { .. }))
        {
            return Ok(());
        }
        let reports = self.database.batch_results(batch_id).await?;
        let timestamp = now();
        let state = if states
            .iter()
            .all(|state| matches!(state, RunState::Completed { .. }))
        {
            RunState::Completed {
                finished_at: timestamp,
            }
        } else if states
            .iter()
            .any(|state| matches!(state, RunState::TimedOut { .. }))
        {
            RunState::TimedOut {
                finished_at: timestamp,
            }
        } else if !reports.is_empty() {
            RunState::Partial {
                finished_at: timestamp,
            }
        } else if states
            .iter()
            .any(|state| matches!(state, RunState::Cancelled { .. }))
        {
            RunState::Cancelled {
                finished_at: timestamp,
            }
        } else {
            RunState::Failed {
                finished_at: timestamp,
                code: "batch_failed".to_owned(),
                message: "no case produced a report".to_owned(),
            }
        };
        let report = SecurityReportFile {
            format: "lattice-estimator/security-report".to_owned(),
            version: 2,
            id: format!("{batch_id}-report"),
            name: request
                .name
                .as_ref()
                .map(|name| format!("{name} security report"))
                .unwrap_or_else(|| format!("Security report {batch_id}")),
            parameter_set_id: request.parameter_set_id,
            reports,
        };
        let report = (!report.reports.is_empty()).then_some(report);
        self.database.finalize_batch(batch_id, state, report).await
    }
}

#[derive(Clone)]
struct CaseContext {
    estimator_problem: EstimatorProblem,
    analysis_model: AnalysisModel,
    resolved_analysis: crate::ResolvedAnalysisSettings,
    estimator_context: crate::EstimatorContext,
}

impl CaseContext {
    fn cache_identity(&self, attack: Attack) -> AttackCacheIdentity {
        AttackCacheIdentity::new(
            self.estimator_problem.clone(),
            self.analysis_model.clone(),
            self.resolved_analysis.clone(),
            attack,
            self.estimator_context.clone(),
        )
    }

    fn applicability(
        &self,
        attack: Attack,
    ) -> Result<crate::SlowAttackApplicability, ServiceError> {
        slow_attack_applicability(&self.estimator_problem, attack).ok_or_else(|| {
            ServiceError::Internal("missing applicability rule for adaptive slow attack".to_owned())
        })
    }

    fn preflight_stop_margin(
        &self,
        policy: &crate::SlowAttackPolicy,
        attack: Attack,
    ) -> Option<bigdecimal::BigDecimal> {
        let EstimatorProblem::Lwe(problem) = &self.estimator_problem else {
            return None;
        };
        preflight_stop_margin(policy, attack, problem)
    }
}

fn fast_attack_groups(
    problem: &crate::Problem,
    existing: &BTreeMap<Attack, AttackResult>,
) -> Vec<Vec<Attack>> {
    let families = match problem {
        crate::Problem::Lwe(_) | crate::Problem::Rlwe(_) | crate::Problem::Glwe(_) => vec![
            vec![
                Attack::Usvp,
                Attack::Bdd,
                Attack::BddHybrid,
                Attack::BddMitmHybrid,
            ],
            vec![Attack::Dual, Attack::DualHybrid],
        ],
        crate::Problem::Ntru(_) => vec![
            vec![Attack::Usvp],
            vec![Attack::Dsd],
            vec![Attack::Bdd, Attack::BddHybrid, Attack::BddMitmHybrid],
        ],
        crate::Problem::Sis(_) => vec![vec![Attack::Lattice]],
    };
    families
        .into_iter()
        .map(|family| {
            family
                .into_iter()
                .filter(|attack| !existing.contains_key(attack))
                .collect::<Vec<_>>()
        })
        .filter(|family| !family.is_empty())
        .collect()
}

async fn wait_for_cancel(database: &Database, batch_id: &str, job_id: &str, notify: &Notify) {
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if database.is_cancel_requested(batch_id).await.unwrap_or(true) {
            return;
        }
        tokio::select! {
            () = notify.notified() => {}
            _ = heartbeat.tick() => {
                if database.heartbeat_job(job_id).await.is_err() {
                    return;
                }
            }
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
}

fn slow_attack_label(attack: Attack) -> &'static str {
    match attack {
        Attack::AroraGb => "arora_gb",
        Attack::Bkw => "bkw",
        _ => unreachable!("only adaptive slow attacks have labels"),
    }
}

fn worker_timing(
    execution: &WorkerAttackExecution,
    request_duration_ms: Option<u64>,
) -> ExecutionTiming {
    ExecutionTiming {
        duration_ms: if execution.duration_scope == crate::DurationScope::RequestGroup {
            request_duration_ms.unwrap_or(execution.duration_ms)
        } else {
            execution.duration_ms
        },
        scope: execution.duration_scope,
        shared_attacks: execution.shared_attacks.clone(),
    }
}

fn preflight_stop_margin(
    policy: &crate::SlowAttackPolicy,
    attack: Attack,
    problem: &crate::LweProblem,
) -> Option<bigdecimal::BigDecimal> {
    let safety_floor = crate::reviewed_preflight_margin_floor(problem, attack)?;
    let requested = match attack {
        Attack::AroraGb => &policy.arora_gb_refined_margin_bits,
        Attack::Bkw => &policy.bkw_margin_bits,
        _ => return None,
    };
    Some(
        requested
            .as_big_decimal()
            .max(bigdecimal::BigDecimal::from(safety_floor)),
    )
}

fn arora_requested_margin(
    policy: &crate::SlowAttackPolicy,
    tier: WorkerPrecisionTier,
) -> &ExactDecimal {
    match tier {
        WorkerPrecisionTier::Coarse => &policy.arora_gb_coarse_margin_bits,
        WorkerPrecisionTier::Refined => &policy.arora_gb_refined_margin_bits,
    }
}

fn reviewed_preflight_security_bits(outcome: &WorkerOutcome) -> Option<&crate::ExactDecimal> {
    match outcome {
        WorkerOutcome::Computed {
            security_bits,
            metrics,
        } if bkw_v5_rule_is_reviewed(metrics) => Some(security_bits),
        _ => None,
    }
}

fn arora_v6_rule_is_reviewed(metrics: &BTreeMap<String, NormalizedMetric>) -> bool {
    matches!(
        metrics.get("preflight_rule_version"),
        Some(NormalizedMetric::Integer { value }) if value.as_bigint() == 6.into()
    )
}

fn arora_v6_policy_fields_are_reviewed(
    tier: WorkerPrecisionTier,
    required: &ExactDecimal,
    requested_margin: &ExactDecimal,
    calibrated_floor: &ExactDecimal,
    effective_margin: &ExactDecimal,
    threshold: &ExactDecimal,
) -> bool {
    let expected_floor = match tier {
        WorkerPrecisionTier::Coarse => crate::ARORA_GB_COARSE_MARGIN_FLOOR_BITS,
        WorkerPrecisionTier::Refined => crate::ARORA_GB_REFINED_MARGIN_FLOOR_BITS,
    };
    let expected_floor = bigdecimal::BigDecimal::from(expected_floor);
    let expected_effective = requested_margin
        .as_big_decimal()
        .max(expected_floor.clone());
    calibrated_floor.as_big_decimal() == expected_floor
        && effective_margin.as_big_decimal() == expected_effective
        && threshold.as_big_decimal() == required.as_big_decimal() + expected_effective
}

fn bkw_v5_rule_is_reviewed(metrics: &BTreeMap<String, NormalizedMetric>) -> bool {
    matches!(
        metrics.get("preflight_rule_version"),
        Some(NormalizedMetric::Integer { value }) if value.as_bigint() == 5.into()
    )
}

fn insert_timeouts(
    attacks: &[Attack],
    timeout_seconds: u64,
    results: &mut BTreeMap<Attack, AttackResult>,
) {
    for attack in attacks {
        results.insert(
            *attack,
            AttackResult {
                attack: *attack,
                cached: false,
                timing: None,
                outcome: AttackOutcome::Timeout { timeout_seconds },
            },
        );
    }
}

fn insert_plan_failures(
    attacks: &[Attack],
    error: &ServiceError,
    results: &mut BTreeMap<Attack, AttackResult>,
) {
    for attack in attacks {
        results.insert(
            *attack,
            AttackResult {
                attack: *attack,
                cached: false,
                timing: None,
                outcome: AttackOutcome::Failed {
                    code: "estimator_plan_failed".to_owned(),
                    message: error.to_string(),
                    retryable: false,
                },
            },
        );
    }
}

fn analysis_warnings(model: &AnalysisModel) -> Vec<String> {
    match model {
        AnalysisModel::CoefficientEmbeddingV1 { warnings, .. } => warnings.clone(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_attack_preflight_margins_use_only_reviewed_error_domains() {
        let policy = crate::SlowAttackPolicy {
            required_security_bits: crate::ExactDecimal::new("128").unwrap(),
            arora_gb_coarse_margin_bits: crate::ExactDecimal::new("80").unwrap(),
            arora_gb_refined_margin_bits: crate::ExactDecimal::new("4").unwrap(),
            bkw_margin_bits: crate::ExactDecimal::new("24").unwrap(),
            forced_attacks: Vec::new(),
        };
        assert_eq!(
            arora_requested_margin(&policy, WorkerPrecisionTier::Coarse),
            &crate::ExactDecimal::new("80").unwrap()
        );
        assert_eq!(
            arora_requested_margin(&policy, WorkerPrecisionTier::Refined),
            &crate::ExactDecimal::new("4").unwrap()
        );
        let problem = |sigma: &str| crate::LweProblem {
            dimension: 1024,
            modulus: crate::PositiveInteger::new("4096").unwrap(),
            samples: crate::SampleCount::Unlimited,
            secret: crate::SecretDistribution::UniformBinary,
            error: crate::ErrorDistribution::DiscreteGaussian {
                standard_deviation: crate::ExactDecimal::new(sigma).unwrap(),
            },
        };
        assert_eq!(
            preflight_stop_margin(&policy, Attack::AroraGb, &problem("0.7")),
            Some(bigdecimal::BigDecimal::from(10))
        );
        assert_eq!(
            preflight_stop_margin(&policy, Attack::AroraGb, &problem("0.6")),
            None
        );
        assert_eq!(
            preflight_stop_margin(&policy, Attack::AroraGb, &problem("4.1")),
            None
        );
        assert_eq!(
            preflight_stop_margin(&policy, Attack::Bkw, &problem("1")),
            Some(bigdecimal::BigDecimal::from(24))
        );
        let mut centered_binomial = problem("1");
        centered_binomial.error = crate::ErrorDistribution::CenteredBinomial { eta: 8 };
        assert_eq!(
            preflight_stop_margin(&policy, Attack::AroraGb, &centered_binomial),
            Some(bigdecimal::BigDecimal::from(10))
        );
        assert_eq!(
            preflight_stop_margin(&policy, Attack::Bkw, &centered_binomial),
            Some(bigdecimal::BigDecimal::from(24))
        );
        let mut finite_bounded = centered_binomial.clone();
        finite_bounded.samples = crate::SampleCount::Finite { count: 4096 };
        assert_eq!(
            preflight_stop_margin(&policy, Attack::AroraGb, &finite_bounded),
            Some(bigdecimal::BigDecimal::from(10))
        );
        assert_eq!(
            preflight_stop_margin(&policy, Attack::Bkw, &finite_bounded),
            Some(bigdecimal::BigDecimal::from(24))
        );
        let mut centered_uniform = problem("1");
        centered_uniform.error = crate::ErrorDistribution::UniformInteger {
            lower: crate::SignedInteger::new("-8").unwrap(),
            upper: crate::SignedInteger::new("8").unwrap(),
        };
        assert_eq!(
            preflight_stop_margin(&policy, Attack::AroraGb, &centered_uniform),
            Some(bigdecimal::BigDecimal::from(10))
        );
        let mut unreviewed_binomial = problem("1");
        unreviewed_binomial.error = crate::ErrorDistribution::CenteredBinomial { eta: 9 };
        assert_eq!(
            preflight_stop_margin(&policy, Attack::AroraGb, &unreviewed_binomial),
            None
        );
        let mut asymmetric_uniform = problem("1");
        asymmetric_uniform.error = crate::ErrorDistribution::UniformInteger {
            lower: crate::SignedInteger::new("0").unwrap(),
            upper: crate::SignedInteger::new("8").unwrap(),
        };
        assert_eq!(
            preflight_stop_margin(&policy, Attack::Bkw, &asymmetric_uniform),
            None
        );
        let mut finite_samples = problem("1");
        finite_samples.samples = crate::SampleCount::Finite { count: 2_000_000 };
        assert_eq!(
            preflight_stop_margin(&policy, Attack::AroraGb, &finite_samples),
            Some(bigdecimal::BigDecimal::from(10))
        );
        let mut ternary_secret = problem("1");
        ternary_secret.secret = crate::SecretDistribution::UniformTernary;
        assert_eq!(
            preflight_stop_margin(&policy, Attack::AroraGb, &ternary_secret),
            Some(bigdecimal::BigDecimal::from(10))
        );
        let mut sparse_secret = problem("1");
        sparse_secret.secret = crate::SecretDistribution::FixedWeightBinary { hamming_weight: 64 };
        assert_eq!(
            preflight_stop_margin(&policy, Attack::AroraGb, &sparse_secret),
            Some(bigdecimal::BigDecimal::from(10))
        );
    }

    #[test]
    fn only_reviewed_preflight_rule_can_skip_an_exact_attack() {
        let outcome = |version: &str| WorkerOutcome::Computed {
            security_bits: crate::ExactDecimal::new("200").unwrap(),
            metrics: BTreeMap::from([(
                "preflight_rule_version".to_owned(),
                NormalizedMetric::Integer {
                    value: crate::SignedInteger::new(version).unwrap(),
                },
            )]),
        };
        assert!(reviewed_preflight_security_bits(&outcome("1")).is_none());
        assert!(reviewed_preflight_security_bits(&outcome("2")).is_none());
        assert!(reviewed_preflight_security_bits(&outcome("3")).is_none());
        assert!(reviewed_preflight_security_bits(&outcome("4")).is_none());
        assert!(reviewed_preflight_security_bits(&outcome("5")).is_some());
        let unknown = WorkerOutcome::PreflightUnknown {
            code: "bounded_search_no_finite_candidate".to_owned(),
            reason: "exact estimation is required".to_owned(),
            raw_result: None,
        };
        assert!(reviewed_preflight_security_bits(&unknown).is_none());
    }

    #[test]
    fn arora_v6_requires_the_reviewed_tier_floor_and_threshold_arithmetic() {
        let decimal = |value: &str| crate::ExactDecimal::new(value).unwrap();
        assert!(arora_v6_policy_fields_are_reviewed(
            WorkerPrecisionTier::Coarse,
            &decimal("128"),
            &decimal("16"),
            &decimal("64"),
            &decimal("64"),
            &decimal("192"),
        ));
        assert!(arora_v6_policy_fields_are_reviewed(
            WorkerPrecisionTier::Refined,
            &decimal("128"),
            &decimal("16"),
            &decimal("10"),
            &decimal("16"),
            &decimal("144"),
        ));
        assert!(!arora_v6_policy_fields_are_reviewed(
            WorkerPrecisionTier::Coarse,
            &decimal("128"),
            &decimal("16"),
            &decimal("32"),
            &decimal("32"),
            &decimal("160"),
        ));
    }

    #[test]
    fn lwe_fast_attacks_keep_the_primal_family_together() {
        let request: EstimateRequest =
            serde_json::from_str(include_str!("../../examples/demo-run.json")).unwrap();
        assert_eq!(
            fast_attack_groups(&request.cases[0].problem, &BTreeMap::new()),
            vec![
                vec![
                    Attack::Usvp,
                    Attack::Bdd,
                    Attack::BddHybrid,
                    Attack::BddMitmHybrid,
                ],
                vec![Attack::Dual, Attack::DualHybrid],
            ]
        );

        let mut existing = BTreeMap::new();
        insert_timeouts(&[Attack::Usvp], 1, &mut existing);
        assert_eq!(
            fast_attack_groups(&request.cases[0].problem, &existing),
            vec![
                vec![Attack::Bdd, Attack::BddHybrid, Attack::BddMitmHybrid],
                vec![Attack::Dual, Attack::DualHybrid],
            ]
        );
    }

    #[test]
    fn failed_plan_becomes_attack_level_failures() {
        let mut results = BTreeMap::new();
        insert_plan_failures(
            &[Attack::Dual, Attack::DualHybrid],
            &ServiceError::Upstream("worker returned 502".to_owned()),
            &mut results,
        );

        for attack in [Attack::Dual, Attack::DualHybrid] {
            assert!(matches!(
                results[&attack].outcome,
                AttackOutcome::Failed {
                    ref code,
                    ref message,
                    retryable: false,
                } if code == "estimator_plan_failed"
                    && message.contains("worker returned 502")
            ));
        }
    }
}
