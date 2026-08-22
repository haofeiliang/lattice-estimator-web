<script lang="ts">
  import { formatDuration, outcomeName } from './display';
  import type { AttackPreflight, AttackResult, ExecutionTiming, PreflightTrace } from './types';

  export let attack: string;
  export let result: AttackResult | undefined = undefined;
  export let preflight: AttackPreflight | undefined = undefined;
  export let staged = false;
  export let forcingExact = false;
  export let forceStatus: 'queued' | 'running' | undefined = undefined;
  export let onForceExact: () => void | Promise<void> = () => {};

  function bits(value?: string) { return value ? Number(value).toFixed(2) : '—'; }
  function thresholdBits(value: string) {
    return Number(value).toLocaleString('zh-CN', { maximumFractionDigits: 2 });
  }
  function timingLabel(timing?: ExecutionTiming, cached = false) {
    if (!timing) return '';
    const scope = timing.scope === 'request_group' ? '同组' : '独立';
    return cached
      ? `原计算用时 ${formatDuration(timing.duration_ms)}（${scope}）`
      : `${scope}计算用时 ${formatDuration(timing.duration_ms)}`;
  }
  function quickResult(trace: PreflightTrace) {
    if (trace.kind === 'threshold_screen') {
      return trace.decision === 'skip_exact'
        ? `确认高于 ${thresholdBits(trace.threshold_bits)} bit`
        : '未形成安全结论';
    }
    if (trace.kind === 'computed') return `${bits(trace.security_bits)} bit`;
    if (trace.kind === 'unknown') return '未找到有限候选';
    if (trace.kind === 'failed') return '快速估算失败';
    return '未执行';
  }
  function quickTiming(trace: PreflightTrace) {
    return trace.kind === 'not_run' ? '' : timingLabel(trace.timing);
  }
  function decision(trace: PreflightTrace) {
    if (trace.kind === 'threshold_screen') {
      if (trace.decision === 'skip_exact') {
        return `快速筛选确认高于 ${thresholdBits(trace.threshold_bits)} bit，跳过精确计算`;
      }
      if (trace.reason === 'time_budget_exhausted') {
        return '快速筛选达到 4 秒预算，继续精确计算';
      }
      if (trace.reason === 'candidate_may_be_below_threshold') {
        return `快速筛选无法确认高于 ${thresholdBits(trace.threshold_bits)} bit，继续精确计算`;
      }
      return '快速筛选未找到有限候选，继续精确计算';
    }
    if (trace.kind === 'computed') {
      return trace.decision === 'skip_exact'
        ? `快速估算不低于 ${bits(trace.threshold_bits)} bit，跳过精确计算`
        : `快速估算低于 ${bits(trace.threshold_bits)} bit，继续精确计算`;
    }
    if (trace.kind === 'unknown') return '快速估算未找到有限候选，因此继续精确计算';
    if (trace.kind === 'failed') return '快速估算失败，保守回退精确计算';
    return trace.reason;
  }
  function exactResult(value?: AttackResult) {
    if (!value) return '等待精确计算';
    if (value.outcome.kind === 'computed') return `${bits(value.outcome.security_bits)} bit`;
    if (value.outcome.kind === 'no_finite_estimate') return `精确 ${attack} 未找到有限成本`;
    if (value.outcome.kind === 'policy_skipped') return '未运行';
    return outcomeName(value);
  }
  function headline(value?: AttackResult) {
    if (forceStatus === 'queued') return '已排队';
    if (forceStatus === 'running') return '精确计算中';
    if (!value) return '等待中';
    if (value.outcome.kind === 'computed') return `${bits(value.outcome.security_bits)} bit`;
    if (value.outcome.kind === 'no_finite_estimate') return '无有限成本';
    if (value.outcome.kind === 'policy_skipped' || value.outcome.kind === 'skipped') return '精确未运行';
    if (value.outcome.kind === 'timeout') return '已超时';
    if (value.outcome.kind === 'failed') return '失败';
    if (value.outcome.kind === 'unsupported') return '不支持';
    return '无结果';
  }
</script>

<div class:slow={staged} class="attack">
  <div class="attack-heading">
    <span>{attack}</span>
    <strong class:result-status={!result?.outcome.security_bits}>{headline(result)}</strong>
  </div>

  {#if staged}
    <div class="stage-timeline">
      <div class="stage-row">
        <span class="stage-marker">1</span>
        <div><small>快速估算</small><strong>{preflight ? quickResult(preflight.trace) : '等待结果'}</strong></div>
        {#if preflight && quickTiming(preflight.trace)}<time>{quickTiming(preflight.trace)}</time>{/if}
      </div>
      <p class:waiting={!preflight} class="stage-decision">{preflight ? decision(preflight.trace) : '等待快速估算与调度决定'}</p>
      <div class="stage-row">
        <span class="stage-marker">2</span>
        <div>
          <small>精确计算</small>
          <strong>{forceStatus === 'queued' ? '等待精确计算' : forceStatus === 'running' ? '正在精确计算' : exactResult(result)}</strong>
          {#if forceStatus || result?.outcome.kind === 'policy_skipped'}
            <button class="force-exact" disabled={forcingExact || Boolean(forceStatus)} on:click={onForceExact}>
              {forcingExact ? '正在提交…' : forceStatus === 'queued' ? '已排队' : forceStatus === 'running' ? '精确计算中' : '强制精确计算'}
            </button>
          {/if}
        </div>
        {#if result?.timing}<time>{timingLabel(result.timing, result.cached)}</time>{/if}
      </div>
    </div>
  {:else if result}
    <small>{outcomeName(result)}</small>
    {#if result.timing}<time class="attack-time">{timingLabel(result.timing, result.cached)}</time>{/if}
  {:else}<small>等待攻击结果</small>{/if}
</div>
