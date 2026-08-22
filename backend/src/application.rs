//! Application use-cases shared by the HTTP API and other transports.
//!
//! This is intentionally a concrete facade, not a framework of repository
//! traits. Domain rules stay in the core types; SQLite and the scheduler stay
//! implementation details behind these operations.

use crate::{
    Attack, EstimateRequest, ParameterSetFile, SecurityReportEntry, SecurityReportFile, Validate,
    attacks_for_problem,
    database::Database,
    error::ServiceError,
    scheduler::SchedulerHandle,
    service::{BatchSnapshot, RunState},
    upstream::Metadata,
};

#[derive(Clone)]
/// Use-case facade joining validation, persistence, and scheduler operations.
pub struct Application {
    database: Database,
    scheduler: SchedulerHandle,
    metadata: Metadata,
    poll_after_seconds: u64,
}

/// Result of submitting or rerunning a batch.
pub struct Submission {
    pub fully_cached: bool,
    pub snapshot: BatchSnapshot,
}

#[derive(Clone, Debug, serde::Serialize)]
/// Lightweight batch row returned by the low-frequency list endpoint.
pub struct BatchSummary {
    pub batch_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_set_id: Option<String>,
    pub case_count: usize,
    pub state: RunState,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, serde::Serialize)]
/// Current independently visible state of one case in a batch.
pub struct CaseProgress {
    pub case_id: String,
    pub case_index: usize,
    pub state: RunState,
    pub revision: u64,
    pub expected_attack_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<crate::CaseExecutionTiming>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub queued_forced_attacks: Vec<Attack>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub running_forced_attacks: Vec<Attack>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SecurityReportEntry>,
}

#[derive(Clone, Debug, serde::Serialize)]
/// Full batch state used by the ETag-aware detail endpoint.
pub struct BatchDetail {
    pub batch_id: String,
    pub state: RunState,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
    pub poll_after_seconds: u64,
    pub request: EstimateRequest,
    pub cases: Vec<CaseProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<SecurityReportFile>,
}

#[derive(Clone, Debug, serde::Serialize)]
/// Public identity and revision returned after importing a parameter set.
pub struct ImportedParameterSet {
    pub id: String,
    pub version: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
/// Lightweight scheme-library row without the full parameter-set document.
pub struct ParameterSetSummary {
    pub id: String,
    pub name: String,
    pub version: u64,
    pub case_count: usize,
    pub created_at: String,
}

impl Application {
    /// Construct the facade from initialized runtime dependencies.
    pub(crate) fn new(
        database: Database,
        scheduler: SchedulerHandle,
        metadata: Metadata,
        poll_after_seconds: u64,
    ) -> Self {
        Self {
            database,
            scheduler,
            metadata,
            poll_after_seconds,
        }
    }

    /// Return immutable upstream estimator capability metadata.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Validate and submit a new estimate request to the scheduler.
    pub async fn estimate(&self, request: EstimateRequest) -> Result<Submission, ServiceError> {
        request.validate()?;
        let (fully_cached, snapshot) = self
            .scheduler
            .submit(request, self.poll_after_seconds)
            .await?;
        Ok(Submission {
            fully_cached,
            snapshot,
        })
    }

    /// Assemble current batch, case, partial-result, and final-report state.
    pub async fn batch(&self, id: &str) -> Result<BatchDetail, ServiceError> {
        let (snapshot, request, jobs) = self
            .database
            .batch_detail(id, self.poll_after_seconds)
            .await?;
        let cases = jobs
            .into_iter()
            .map(|job| {
                let parameter = request.cases.get(job.case_index).ok_or_else(|| {
                    ServiceError::Internal(format!(
                        "job '{}' refers to missing case index {}",
                        job.case_id, job.case_index
                    ))
                })?;
                let execution = job
                    .execution
                    .clone()
                    .or_else(|| job.result.as_ref().map(|result| result.execution.clone()));
                Ok(CaseProgress {
                    case_id: job.case_id,
                    case_index: job.case_index,
                    state: job.state,
                    revision: job.revision,
                    expected_attack_count: attacks_for_problem(&parameter.problem).len(),
                    execution,
                    queued_forced_attacks: job.queued_forced_attacks,
                    running_forced_attacks: job.running_forced_attacks,
                    result: job.result,
                })
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;
        Ok(BatchDetail {
            batch_id: snapshot.batch_id,
            state: snapshot.state,
            revision: snapshot.revision,
            created_at: snapshot.created_at,
            updated_at: snapshot.updated_at,
            poll_after_seconds: snapshot.poll_after_seconds,
            request,
            cases,
            report: snapshot.report,
        })
    }

    /// List recent batches without loading cases or reports.
    pub async fn batches(&self) -> Result<Vec<BatchSummary>, ServiceError> {
        Ok(self
            .database
            .list_batch_headers(200)
            .await?
            .into_iter()
            .map(|header| BatchSummary {
                batch_id: header.batch_id,
                name: header
                    .request
                    .name
                    .clone()
                    .unwrap_or_else(|| default_run_name(&header.request)),
                parameter_set_id: header.request.parameter_set_id.clone(),
                case_count: header.request.cases.len(),
                state: header.state,
                revision: header.revision,
                created_at: header.created_at,
                updated_at: header.updated_at,
            })
            .collect())
    }

    /// Request cancellation and return the resulting batch snapshot.
    pub async fn cancel(&self, id: &str) -> Result<BatchSnapshot, ServiceError> {
        self.scheduler.cancel(id, self.poll_after_seconds).await
    }

    /// Submit the original request as a new run.
    pub async fn rerun(&self, id: &str) -> Result<Submission, ServiceError> {
        self.estimate(self.database.batch_request(id).await?).await
    }

    /// Queue one previously skipped slow attack inside its existing batch and case.
    pub async fn force_exact_attack(
        &self,
        batch_id: &str,
        case_id: &str,
        attack: Attack,
    ) -> Result<BatchSnapshot, ServiceError> {
        self.scheduler
            .force_exact_attack(batch_id, case_id, attack, self.poll_after_seconds)
            .await
    }

    /// Return the final report, rejecting non-terminal or report-less batches.
    pub async fn report(&self, id: &str) -> Result<SecurityReportFile, ServiceError> {
        let detail = self.batch(id).await?;
        if !detail.state.terminal() {
            return Err(ServiceError::Conflict(
                "batch is still running and has no exportable final report".to_owned(),
            ));
        }
        detail.report.ok_or_else(|| {
            ServiceError::Conflict("batch does not have an exportable report yet".to_owned())
        })
    }

    /// Delete one batch through the same atomic bulk-delete path.
    pub async fn delete_batch(&self, id: String) -> Result<(), ServiceError> {
        self.delete_batches(vec![id]).await
    }

    /// Delete selected batch histories.
    pub async fn delete_batches(&self, ids: Vec<String>) -> Result<(), ServiceError> {
        self.database.delete_batches(ids).await
    }

    /// List saved parameter sets for the scheme library.
    pub async fn parameter_sets(&self) -> Result<Vec<ParameterSetSummary>, ServiceError> {
        self.database.list_parameter_sets().await
    }

    /// Export one saved parameter set as a v2 document.
    pub async fn parameter_set(&self, id: &str) -> Result<ParameterSetFile, ServiceError> {
        self.database.export_parameter_set(id).await
    }

    /// Validate and insert or explicitly replace a v2 parameter set.
    pub async fn import_parameter_set(
        &self,
        value: ParameterSetFile,
        replace: bool,
    ) -> Result<ImportedParameterSet, ServiceError> {
        value.validate()?;
        self.database.import_parameter_set(value, replace).await
    }

    /// Delete one saved parameter set.
    pub async fn delete_parameter_set(&self, id: &str) -> Result<(), ServiceError> {
        self.delete_parameter_sets(vec![id.to_owned()]).await
    }

    /// Delete selected parameter sets atomically.
    pub async fn delete_parameter_sets(&self, ids: Vec<String>) -> Result<(), ServiceError> {
        self.database.delete_parameter_sets(ids).await
    }
}

fn default_run_name(request: &EstimateRequest) -> String {
    // Keep generated names deterministic so list refreshes never rename a batch.
    match request.cases.as_slice() {
        [case] => case.name.clone(),
        [first, rest @ ..] => format!("{} 等 {} 个 cases", first.name, rest.len() + 1),
        [] => "未命名批次".to_owned(),
    }
}
