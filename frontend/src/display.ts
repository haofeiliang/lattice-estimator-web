import type { AttackResult, RunState } from './types';

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

export function outcomeName(result: AttackResult): string {
  switch (result.outcome.kind) {
    case 'computed': return result.cached ? '已计算（来自缓存）' : '已计算';
    case 'no_finite_estimate': return '当前攻击模型未找到有限成本';
    case 'preflight_unknown': return '快速估算未确定，已回退精确估算';
    case 'timeout': return '运行超时';
    case 'unsupported': return '当前参数不受支持';
    case 'failed': return '估算失败';
    case 'policy_skipped': return result.outcome.code === 'attack_preflight_above_threshold'
      ? '快速估算高于安全阈值，已跳过精确攻击'
      : '根据运行策略跳过';
    case 'skipped': return '已跳过';
    default: return '未知结果';
  }
}

export function technicalDetail(result: AttackResult): string {
  return result.outcome.reason ?? result.outcome.message ?? '';
}
