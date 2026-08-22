// Frontend mirror of the current Rust JSON contract; no legacy response shapes.
/** Persistent batch or case lifecycle state with variant-specific timestamps. */
export type RunState = { kind: string; [key: string]: unknown };

/** Secret or error coefficient distribution accepted by the current API. */
export type Distribution =
  | { kind: 'uniform_binary' }
  | { kind: 'uniform_ternary' }
  | { kind: 'sparse_ternary' }
  | { kind: 'fixed_weight_binary'; hamming_weight: number }
  | { kind: 'fixed_weight_ternary'; positive_weight: number; negative_weight: number }
  | { kind: 'discrete_gaussian'; standard_deviation: string }
  | { kind: 'centered_binomial'; eta: number }
  | { kind: 'uniform_integer'; lower: string; upper: string };

/** Public problem families edited by the browser UI. */
export type Problem = {
  kind: string;
  dimension?: number;
  modulus?: string;
  samples?: { kind: 'unlimited' } | { kind: 'finite'; count: number };
  secret?: Distribution;
  error?: Distribution;
  negacyclic_ring?: { polynomial_degree: number; ciphertext_modulus: string };
  columns?: number;
  length_bound?: string;
  norm?: string;
  structure?: string;
};

/** One named problem and analysis choice inside a parameter set. */
export type ParameterCase = {
  id: string;
  name: string;
  description?: string;
  tags: string[];
  problem: Problem;
  analysis: Record<string, unknown>;
};

/** Importable/exportable version-2 scheme document. */
export type ParameterSet = {
  format: 'lattice-estimator/parameter-set';
  version: 2;
  id: string;
  name: string;
  description?: string;
  tags: string[];
  cases: ParameterCase[];
};

/** Batch submission contract sent to the Rust backend. */
export type EstimateRequest = {
  name?: string;
  parameter_set_id?: string;
  cases: ParameterCase[];
  mode: 'rough' | 'normal';
  timeout_seconds: number;
  slow_attack_policy?: {
    required_security_bits: string;
    arora_gb_coarse_margin_bits: string;
    arora_gb_refined_margin_bits: string;
    bkw_margin_bits: string;
    forced_attacks?: Array<'arora_gb' | 'bkw'>;
  };
};

/** Scheme source retained while editing and rerunning an existing batch. */
export type EstimateDraftSource = {
  sequence: number;
  batchId: string;
  request: EstimateRequest;
  focusCaseId?: string;
};

/** Final attack outcome with cache and execution-timing metadata. */
export type AttackResult = {
  attack: string;
  cached: boolean;
  timing?: ExecutionTiming;
  outcome: { kind: string; security_bits?: string; reason?: string; message?: string; code?: string };
};

/** Real worker duration and whether it belongs to a shared attack group. */
export type ExecutionTiming = {
  duration_ms: number;
  scope: 'attack' | 'request_group';
  shared_attacks?: string[];
};

/** Auditable slow-attack scheduling trace, never a final security conclusion. */
export type PreflightTrace =
  | {
      kind: 'threshold_screen'; precision_tier: 'coarse' | 'refined';
      required_security_bits: string; requested_margin_bits: string;
      calibrated_margin_floor_bits: string; effective_margin_bits: string;
      threshold_bits: string; reason: string; timing: ExecutionTiming;
      metrics: Record<string, { kind: string; value?: string | boolean }>;
      decision: 'run_exact' | 'skip_exact';
    }
  | {
      kind: 'computed'; security_bits: string; timing: ExecutionTiming;
      metrics: Record<string, { kind: string; value?: string | boolean }>;
      effective_margin_bits: string; threshold_bits: string;
      decision: 'run_exact' | 'skip_exact';
    }
  | { kind: 'unknown'; code: string; reason: string; timing: ExecutionTiming; raw_result?: unknown; decision: 'run_exact' }
  | { kind: 'failed'; code: string; message: string; timing?: ExecutionTiming; decision: 'run_exact' }
  | { kind: 'not_run'; code: string; reason: string };

/** Preflight trace paired with its canonical attack name. */
export type AttackPreflight = { attack: string; trace: PreflightTrace };

/** Case wall-clock interval excluding its initial queue wait. */
export type CaseExecutionTiming = { started_at: string; finished_at?: string };

/** Progressive or final report data for one parameter case. */
export type ReportEntry = {
  case: ParameterCase;
  execution: CaseExecutionTiming;
  summary: { security_bits?: string; best_attack?: string; complete: boolean; fast_estimate: boolean; warnings: string[] };
  preflights: AttackPreflight[];
  attacks: AttackResult[];
};

/** Current independently pollable progress of one batch case. */
export type CaseProgress = {
  case_id: string;
  case_index: number;
  state: RunState;
  revision: number;
  expected_attack_count: number;
  execution?: CaseExecutionTiming;
  queued_forced_attacks?: Array<'arora_gb' | 'bkw'>;
  running_forced_attacks?: Array<'arora_gb' | 'bkw'>;
  result?: ReportEntry;
};

/** Lightweight item shown in the batch list. */
export type BatchSummary = {
  batch_id: string;
  name: string;
  parameter_set_id?: string;
  case_count: number;
  state: RunState;
  revision: number;
  created_at: string;
  updated_at: string;
};

/** ETag-polled batch detail including all cases and optional final report. */
export type BatchDetail = {
  batch_id: string;
  state: RunState;
  revision: number;
  created_at: string;
  updated_at: string;
  poll_after_seconds: number;
  request: EstimateRequest;
  cases: CaseProgress[];
  report?: { reports: ReportEntry[] };
};

/** Lightweight item shown in the scheme library. */
export type ParameterSetSummary = { id: string; name: string; version: number; case_count: number; created_at: string };
