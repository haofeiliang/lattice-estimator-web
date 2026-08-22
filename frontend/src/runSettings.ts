/** Shared run-policy state and lossless conversion to the batch request contract. */
import type { EstimateRequest, ParameterCase } from './types';

export type RunSettings = {
  mode: 'rough' | 'normal';
  timeoutSeconds: number;
  requiredSecurityBits: string;
  aroraGbCoarseMarginBits: string;
  aroraGbRefinedMarginBits: string;
  bkwMarginBits: string;
  forceAroraGb: boolean;
  forceBkw: boolean;
};

export function defaultRunSettings(): RunSettings {
  return {
    mode: 'normal',
    timeoutSeconds: 3600,
    requiredSecurityBits: '128',
    aroraGbCoarseMarginBits: '64',
    aroraGbRefinedMarginBits: '10',
    bkwMarginBits: '10',
    forceAroraGb: false,
    forceBkw: false,
  };
}

export function runSettingsFromRequest(request: EstimateRequest): RunSettings {
  const forced = request.slow_attack_policy?.forced_attacks ?? [];
  return {
    mode: request.mode,
    timeoutSeconds: request.timeout_seconds,
    requiredSecurityBits: request.slow_attack_policy?.required_security_bits ?? '128',
    aroraGbCoarseMarginBits: request.slow_attack_policy?.arora_gb_coarse_margin_bits ?? '64',
    aroraGbRefinedMarginBits: request.slow_attack_policy?.arora_gb_refined_margin_bits ?? '10',
    bkwMarginBits: request.slow_attack_policy?.bkw_margin_bits ?? '10',
    forceAroraGb: forced.includes('arora_gb'),
    forceBkw: forced.includes('bkw'),
  };
}

export function buildEstimateRequest(input: {
  name: string;
  parameterSetId?: string;
  cases: ParameterCase[];
  settings: RunSettings;
}): EstimateRequest {
  const { settings } = input;
  const forcedAttacks: Array<'arora_gb' | 'bkw'> = [];
  if (settings.forceAroraGb) forcedAttacks.push('arora_gb');
  if (settings.forceBkw) forcedAttacks.push('bkw');
  return {
    ...(input.name.trim() ? { name: input.name.trim() } : {}),
    ...(input.parameterSetId ? { parameter_set_id: input.parameterSetId } : {}),
    cases: input.cases,
    mode: settings.mode,
    timeout_seconds: settings.timeoutSeconds,
    ...(settings.mode === 'normal' ? {
      slow_attack_policy: {
        required_security_bits: settings.requiredSecurityBits,
        arora_gb_coarse_margin_bits: settings.aroraGbCoarseMarginBits,
        arora_gb_refined_margin_bits: settings.aroraGbRefinedMarginBits,
        bkw_margin_bits: settings.bkwMarginBits,
        ...(forcedAttacks.length ? { forced_attacks: forcedAttacks } : {}),
      },
    } : {}),
  };
}
