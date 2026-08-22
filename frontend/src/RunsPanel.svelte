<script lang="ts">
  import { onMount } from 'svelte';
  import { api, apiResponse, download, userMessage } from './api';
  import AttackCard from './AttackCard.svelte';
  import AttackGroupCard from './AttackGroupCard.svelte';
  import { formatDuration, stateName } from './display';
  import ProblemSummary from './ProblemSummary.svelte';
  import type { BatchDetail, BatchSummary, EstimateRequest, ReportEntry } from './types';

  export let onEditRequest: (request: EstimateRequest, batchId: string, focusCaseId?: string) => void = () => {};
  export let selectedBatchId = '';
  export let onSelectionChange: (batchId: string, replace: boolean) => void = () => {};

  let records: BatchSummary[] = [];
  let selected = selectedBatchId;
  let detail: BatchDetail | undefined;
  let detailEtag = '';
  let detailTimer: number | undefined;
  let checkedIds = new Set<string>();
  let deleting = false;
  let forcingExact = '';
  let message = '';
  let clock = Date.now();
  $: deletableIds = records.filter(record => terminal(record.state.kind)).map(record => record.batch_id);
  $: allDeletableChecked = deletableIds.length > 0 && deletableIds.every(id => checkedIds.has(id));
  $: if (selectedBatchId !== selected) selectBatch(selectedBatchId, false);

  function bits(value?: string) { return value ? Number(value).toFixed(2) : '—'; }
  function terminal(kind?: string) { return Boolean(kind && ['completed', 'partial', 'timed_out', 'cancelled', 'failed'].includes(kind)); }
  function runTitle(current: BatchDetail) {
    const name = current.request.name?.trim();
    if (name) return name;
    const cases = current.request.cases;
    return cases.length === 1 ? cases[0].name : `${cases[0].name} 等 ${cases.length} 组参数`;
  }
  function forced(current: BatchDetail) {
    return current.request.slow_attack_policy?.forced_attacks ?? [];
  }
  type SlowAttack = 'arora_gb' | 'bkw';
  const slowAttacks: SlowAttack[] = ['arora_gb', 'bkw'];
  const primalAttacks = ['usvp', 'bdd', 'bdd_hybrid', 'bdd_mitm_hybrid'];
  const dualAttacks = ['dual', 'dual_hybrid'];
  const groupedAttacks = new Set([...slowAttacks, ...primalAttacks, ...dualAttacks]);
  function usesLweGroups(kind: string) { return ['lwe', 'rlwe', 'glwe'].includes(kind); }
  function expectedAttacks(kind: string, mode: EstimateRequest['mode']) {
    if (usesLweGroups(kind)) {
      return mode === 'rough' ? [...primalAttacks, ...dualAttacks] : [...slowAttacks, ...primalAttacks, ...dualAttacks];
    }
    if (kind === 'ntru') return ['usvp', 'dsd', 'bdd', 'bdd_hybrid', 'bdd_mitm_hybrid'];
    if (kind === 'sis') return ['lattice'];
    return [];
  }
  function groupResults(entry: ReportEntry | undefined, attacks: string[]) {
    return attacks.flatMap(attack => entry?.attacks.filter(item => item.attack === attack) ?? []);
  }
  function remainingAttacks(expected: string[], grouped: boolean) {
    return expected.filter(attack => !slowAttacks.some(slow => slow === attack) && (!grouped || !groupedAttacks.has(attack)));
  }
  function visibleWarnings(entry?: ReportEntry) {
    return entry?.summary.warnings.filter(warning => !warning.startsWith('慢攻击的专用快速估算已达到目标安全值与余量')) ?? [];
  }
  function forcedAttackStatus(progress: BatchDetail['cases'][number] | undefined, attack: SlowAttack) {
    if (progress?.running_forced_attacks?.includes(attack)) return 'running' as const;
    if (progress?.queued_forced_attacks?.includes(attack)) return 'queued' as const;
    return undefined;
  }
  function elapsed(execution?: { started_at: string; finished_at?: string }) {
    if (!execution) return '尚未开始';
    const started = Date.parse(execution.started_at);
    const finished = execution.finished_at ? Date.parse(execution.finished_at) : clock;
    if (!Number.isFinite(started) || !Number.isFinite(finished)) return '—';
    return formatDuration(Math.max(0, finished - started));
  }

  async function refreshList() {
    records = await api<BatchSummary[]>('/v1/batches');
    const available = new Set(records.map(record => record.batch_id));
    checkedIds = new Set([...checkedIds].filter(id => available.has(id)));
    if (selected && !available.has(selected)) selectBatch(records[0]?.batch_id ?? '', true, true);
    else if (!selected && records[0]) selectBatch(records[0].batch_id, true, true);
  }

  function selectBatch(id: string, notify = true, replace = false) {
    if (detailTimer !== undefined) window.clearTimeout(detailTimer);
    selected = id;
    detail = undefined;
    detailEtag = '';
    if (notify) onSelectionChange(id, replace);
    if (id) void pollDetail();
  }

  async function pollDetail() {
    if (detailTimer !== undefined) window.clearTimeout(detailTimer);
    const batchId = selected;
    if (!batchId) return;
    try {
      const response = await apiResponse<BatchDetail>(`/v1/batches/${batchId}`, {
        headers: detailEtag ? { 'If-None-Match': detailEtag } : undefined,
      });
      if (selected !== batchId) return;
      if (response.etag) detailEtag = response.etag;
      if (response.data) detail = response.data;
    } catch (error) {
      if (selected === batchId) message = userMessage(error);
    }
    if (selected === batchId && !terminal(detail?.state.kind)) {
      const delay = Math.max(1, detail?.poll_after_seconds ?? 1) * 1000;
      detailTimer = window.setTimeout(pollDetail, delay);
    }
  }

  function toggleChecked(id: string) {
    const next = new Set(checkedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    checkedIds = next;
  }
  function toggleAll() {
    checkedIds = allDeletableChecked ? new Set() : new Set(deletableIds);
  }
  async function deleteChecked() {
    const ids = [...checkedIds];
    if (!ids.length || !confirm(`删除选中的 ${ids.length} 个已结束批次？计算缓存会保留。`)) return;
    deleting = true;
    message = '';
    try {
      await api('/v1/batches/bulk-delete', { method: 'POST', body: JSON.stringify({ ids }) });
      checkedIds = new Set();
      if (ids.includes(selected)) selectBatch('', true, true);
      await refreshList();
      message = `已删除 ${ids.length} 个批次`;
    } catch (error) {
      message = userMessage(error);
    } finally {
      deleting = false;
    }
  }
  async function action(path: string, method = 'POST') {
    try {
      await api(path, { method });
      detailEtag = '';
      await Promise.all([refreshList(), pollDetail()]);
    } catch (error) { message = userMessage(error); }
  }
  async function exportReport() {
    if (!detail || !terminal(detail.state.kind) || !detail.report) return;
    try { download(`${selected}.lattice-report.json`, await api(`/v1/batches/${selected}/export`)); }
    catch (error) { message = userMessage(error); }
  }

  async function forceExactAttack(caseId: string, attack: SlowAttack) {
    if (!detail) return;
    const key = `${caseId}:${attack}`;
    forcingExact = key;
    message = '';
    try {
      await api(
        `/v1/batches/${encodeURIComponent(detail.batch_id)}/cases/${encodeURIComponent(caseId)}/attacks/${attack}/force-exact`,
        { method: 'POST' },
      );
      detailEtag = '';
      await Promise.all([refreshList(), pollDetail()]);
      message = `已在当前批次中开始精确执行 ${attack}`;
    } catch (error) {
      message = userMessage(error);
    } finally {
      forcingExact = '';
    }
  }

  function editParameters(focusCaseId?: string) {
    if (detail) onEditRequest(detail.request, detail.batch_id, focusCaseId);
  }

  onMount(() => {
    refreshList().catch(error => message = userMessage(error));
    const listTimer = window.setInterval(() => refreshList().catch(() => {}), 2500);
    const clockTimer = window.setInterval(() => clock = Date.now(), 1000);
    return () => {
      window.clearInterval(listTimer);
      window.clearInterval(clockTimer);
      if (detailTimer !== undefined) window.clearTimeout(detailTimer);
    };
  });
</script>

<div class="split runs">
  <aside class="panel list-pane">
    <header><div><p class="eyebrow">运行历史</p><h2>运行批次</h2></div><button on:click={refreshList}>刷新</button></header>
    {#if records.length > 0}
      <div class="bulk-toolbar">
        <button class="ghost" disabled={deleting || deletableIds.length === 0} on:click={toggleAll}>{allDeletableChecked ? '取消全选' : '全选可删除项'}</button>
        <button class="danger" disabled={deleting || checkedIds.size === 0} on:click={deleteChecked}>{deleting ? '删除中…' : `删除所选 (${checkedIds.size})`}</button>
      </div>
    {/if}
    {#if records.length === 0}<p class="empty">还没有运行记录。</p>{/if}
    {#each records as record}
      <div class="selectable-list-row">
        <label class="list-check" title={terminal(record.state.kind) ? '选择批次' : '运行中的批次需先取消或等待结束'}>
          <input type="checkbox" disabled={!terminal(record.state.kind)} checked={checkedIds.has(record.batch_id)} on:change={() => toggleChecked(record.batch_id)} aria-label={`选择批次 ${record.name}`} />
        </label>
        <button class:selected={selected === record.batch_id} class="list-item" on:click={() => selectBatch(record.batch_id)}>
          <span class="row"><strong>{record.name}</strong><span class="status {record.state.kind}">{stateName(record.state)}</span></span>
          <span>{record.parameter_set_id ? `方案 ${record.parameter_set_id} · ` : ''}{record.case_count} 组参数 · {new Date(record.updated_at).toLocaleString()}</span>
        </button>
      </div>
    {/each}
  </aside>
  <section class="panel detail-pane">
    {#if detail}
      <header>
        <div>
          <p class="eyebrow">批次详情</p>
          <h2>{runTitle(detail)}</h2>
          <div class="run-meta"><code>{detail.batch_id}</code><span>修订 {detail.revision}</span><span class="status {detail.state.kind}">{stateName(detail.state)}</span></div>
          {#if forced(detail).length}<div class="forced-badges"><span>手动慢攻击</span>{#each forced(detail) as attack}<code>{attack}</code>{/each}</div>{/if}
        </div>
        <div class="actions">
          {#if !terminal(detail.state.kind)}<button on:click={() => action(`/v1/batches/${selected}/cancel`)}>取消</button>{/if}
          <button on:click={() => action(`/v1/batches/${selected}/rerun`)}>重跑</button>
          <button class="secondary" on:click={() => editParameters()}>修改参数后重新估算</button>
          {#if terminal(detail.state.kind) && detail.report}<button on:click={exportReport}>导出报告</button>{/if}
          {#if terminal(detail.state.kind)}<button class="danger" on:click={() => confirm('删除这个批次？计算缓存会保留。') && action(`/v1/batches/${selected}`, 'DELETE')}>删除</button>{/if}
        </div>
      </header>
      {#each detail.request.cases as parameter, index}
        {@const progress = detail.cases.find(item => item.case_id === parameter.id)}
        {@const result = progress?.result ?? detail.report?.reports.find(item => item.case.id === parameter.id)}
        {@const execution = progress?.execution ?? result?.execution}
        {@const expected = expectedAttacks(parameter.problem.kind, detail.request.mode)}
        {@const lweGroups = usesLweGroups(parameter.problem.kind)}
        {@const returned = expected.filter(attack => result?.attacks.some(item => item.attack === attack)).length}
        <article class="result-card">
          <header>
            <div><p class="eyebrow">第 {index + 1} 组参数</p><h3>{parameter.name}</h3><div class="run-meta"><code>{parameter.id}</code><span class="status {progress?.state.kind ?? 'queued'}">{stateName(progress?.state)}</span></div></div>
            <div class="result-card-actions">
              <button class="ghost adjust-case" on:click={() => editParameters(parameter.id)}>调整此参数</button>
              <span class="case-duration"><small>{execution?.finished_at ? '总耗时' : '已运行'}</small><strong>{elapsed(execution)}</strong></span>
              <span class="security-bit">
                {#if result?.summary.security_bits}<small>{terminal(progress?.state.kind) ? '安全' : '当前最低'}</small><strong>{bits(result.summary.security_bits)} bit</strong>{:else}<strong>—</strong>{/if}
              </span>
            </div>
          </header>
          <ProblemSummary problem={parameter.problem} />
          <p class="case-progress">已返回 {returned}/{expected.length} 项攻击</p>
          {#if expected.length}
            <div class="attack-grid">
              {#each slowAttacks as attack}
                {#if expected.includes(attack)}
                  <AttackCard
                    {attack}
                    staged
                    result={result?.attacks.find(item => item.attack === attack)}
                    preflight={result?.preflights.find(item => item.attack === attack)}
                    forcingExact={forcingExact === `${parameter.id}:${attack}`}
                    forceStatus={forcedAttackStatus(progress, attack)}
                    onForceExact={() => forceExactAttack(parameter.id, attack)}
                  />
                {/if}
              {/each}
              {#if lweGroups}
                <AttackGroupCard title="Primal / BDD" variant="primal" attacks={primalAttacks} results={groupResults(result, primalAttacks)} bestAttack={result?.summary.best_attack} />
              {/if}
              {#if lweGroups}
                <AttackGroupCard title="Dual" variant="dual" attacks={dualAttacks} results={groupResults(result, dualAttacks)} bestAttack={result?.summary.best_attack} />
              {/if}
              {#each remainingAttacks(expected, lweGroups) as attack}
                <AttackCard {attack} result={result?.attacks.find(item => item.attack === attack)} />
              {/each}
            </div>
            {#each visibleWarnings(result) as warning}<p class="warning">{warning}</p>{/each}
          {:else}
            <p class="empty">这类参数没有可运行的攻击。</p>
          {/if}
        </article>
      {/each}
    {:else if selected}<div class="empty centered">正在载入批次详情…</div>
    {:else}<div class="empty centered">从左侧选择一个批次查看参数和结果。</div>{/if}
    {#if message}<p class="notice">{message}</p>{/if}
  </section>
</div>
