/** Chinese labels and consistent duration formatting for report presentation. */
import type { AttackResult, RunState } from './types';

/** Translate persistent batch/job state to its user-facing label. */
export function stateName(state?: RunState): string {
  return ({
    queued: '等待中',
    running: '运行中',
    cancel_requested: '取消中',
    cancelled: '已取消',
    completed: '已完成',
    partial: '部分完成',
    timed_out: '已超时',
    interrupted: '已中断',
    failed: '失败',
  } as Record<string, string>)[state?.kind ?? ''] ?? '未知状态';
}

/** Translate an attack outcome without translating the attack identifier. */
export function outcomeName(result: AttackResult): string {
  switch (result.outcome.kind) {
    case 'computed': return result.cached ? '已计算（来自缓存）' : '已计算';
    case 'no_finite_estimate': return '当前攻击模型未找到有限成本';
    case 'preflight_unknown': return '快速估算未确定，已回退精确估算';
    case 'timeout': return '运行超时';
    case 'failed': return '估算失败';
    case 'policy_skipped': return result.outcome.code === 'attack_preflight_above_threshold'
      ? '快速估算高于安全阈值，已跳过精确攻击'
      : '根据运行策略跳过';
    case 'skipped': return '已跳过';
    default: return '未知结果';
  }
}

/** Format milliseconds as <1 ms, ms, seconds, or minutes. */
export function formatDuration(durationMs?: number): string {
  if (durationMs === undefined) return '—';
  if (durationMs < 1) return '<1 ms';
  if (durationMs < 1000) return `${durationMs} ms`;
  if (durationMs < 60_000) return `${(durationMs / 1000).toFixed(2)} s`;
  const minutes = Math.floor(durationMs / 60_000);
  const seconds = Math.floor((durationMs % 60_000) / 1000);
  return `${minutes}m ${String(seconds).padStart(2, '0')}s`;
}
