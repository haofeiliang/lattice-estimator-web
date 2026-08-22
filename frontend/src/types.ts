export type RunState = { kind: string; [key: string]: unknown };

export type Distribution =
  | { kind: 'uniform_binary' }
  | { kind: 'uniform_ternary' }
  | { kind: 'sparse_ternary' }
  | { kind: 'fixed_weight_binary'; hamming_weight: number }
  | { kind: 'fixed_weight_ternary'; positive_weight: number; negative_weight: number }
  | { kind: 'discrete_gaussian'; standard_deviation: string }
  | { kind: 'centered_binomial'; eta: number }
  | { kind: 'uniform_integer'; lower: string; upper: string };

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

export type ParameterCase = {
  id: string;
  name: string;
  description?: string;
  tags: string[];
  problem: Problem;
  analysis: Record<string, unknown>;
};

export type ParameterSet = {
  format: 'lattice-estimator/parameter-set';
  version: 2;
  id: string;
  name: string;
  description?: string;
  tags: string[];
  cases: ParameterCase[];
};

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

export type EstimateDraftSource = {
  sequence: number;
  batchId: string;
  request: EstimateRequest;
  focusCaseId?: string;
};

export type AttackResult = {
  attack: string;
  cached: boolean;
  timing?: ExecutionTiming;
  outcome: { kind: string; security_bits?: string; reason?: string; message?: string; code?: string };
};

export type ExecutionTiming = {
  duration_ms: number;
  scope: 'attack' | 'request_group';
  shared_attacks?: string[];
};

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

export type AttackPreflight = { attack: string; trace: PreflightTrace };

export type CaseExecutionTiming = { started_at: string; finished_at?: string };

export type ReportEntry = {
  case: ParameterCase;
  execution: CaseExecutionTiming;
  summary: { security_bits?: string; best_attack?: string; complete: boolean; fast_estimate: boolean; warnings: string[] };
  preflights: AttackPreflight[];
  attacks: AttackResult[];
};

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

export type ParameterSetSummary = { id: string; name: string; version: number; case_count: number; created_at: string };
