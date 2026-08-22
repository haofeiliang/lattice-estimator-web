<script lang="ts">
  import { formatDuration, outcomeName } from './display';
  import type { AttackResult, ExecutionTiming } from './types';

  export let title: string;
  export let variant: 'primal' | 'dual' | 'other' = 'other';
  export let attacks: string[] = [];
  export let results: AttackResult[] = [];
  export let bestAttack: string | undefined;

  function bits(value?: string) { return value ? Number(value).toFixed(2) : '—'; }
  function timingKey(result: AttackResult) {
    if (!result.timing) return `missing:${result.attack}`;
    return JSON.stringify({ cached: result.cached, ...result.timing });
  }
  function distinctTimings(items: AttackResult[]) {
    const unique = new Map<string, { timing?: ExecutionTiming; cached: boolean }>();
    for (const result of items) {
      unique.set(timingKey(result), { timing: result.timing, cached: result.cached });
    }
    return [...unique.values()];
  }
  function timingLabel(timing?: ExecutionTiming, cached = false) {
    if (!timing) return '耗时未知';
    const duration = formatDuration(timing.duration_ms);
    if (cached) return `原计算用时 ${duration}`;
    return timing.scope === 'request_group'
      ? `同组计算用时 ${duration}`
      : `独立计算用时 ${duration}`;
  }
  $: timings = distinctTimings(results);
</script>

<section class="attack-group {variant}" aria-label={`${title} 攻击组`}>
  <header>
    <div>
      <strong>{title}</strong>
      <small>{results.length === attacks.length ? `${attacks.length} 项攻击` : `已返回 ${results.length}/${attacks.length}`}</small>
    </div>
    {#if timings.length === 1}
      {@const entry = timings[0]}
      <time>{timingLabel(entry.timing, entry.cached)}</time>
    {:else if timings.length > 1}<span class="group-timing">分批完成</span>
    {:else}<span class="group-timing">等待结果</span>{/if}
  </header>
  <div class="group-results">
    {#each attacks as attack}
      {@const result = results.find(item => item.attack === attack)}
      <div class:best={Boolean(result && attack === bestAttack)} class:waiting={!result} class="group-result-row">
        <div class="group-attack-name">
          <code>{attack}</code>
          {#if result && attack === bestAttack}<span>最低</span>{/if}
        </div>
        <div class="group-result-value">
          {#if result?.outcome.security_bits}<strong>{bits(result.outcome.security_bits)} <small>bit</small></strong>
          {:else}<strong class="result-status">—</strong>{/if}
          <small>{result ? outcomeName(result) : '等待结果'}</small>
          {#if timings.length > 1 && result?.timing}
            <time>{timingLabel(result.timing, result.cached)}</time>
          {/if}
        </div>
      </div>
    {/each}
  </div>
</section>
