<script lang="ts">
  import { onMount } from 'svelte';
  import { api, apiResponse, download, userMessage } from './api';
  import { outcomeName, stateName, technicalDetail } from './display';
  import ProblemSummary from './ProblemSummary.svelte';
  import type { BatchDetail, BatchSummary } from './types';

  let records: BatchSummary[] = [];
  let selected = '';
  let detail: BatchDetail | undefined;
  let detailEtag = '';
  let detailTimer: number | undefined;
  let checkedIds = new Set<string>();
  let deleting = false;
  let message = '';
  $: deletableIds = records.filter(record => terminal(record.state.kind)).map(record => record.batch_id);
  $: allDeletableChecked = deletableIds.length > 0 && deletableIds.every(id => checkedIds.has(id));

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

  async function refreshList() {
    records = await api<BatchSummary[]>('/v1/batches');
    const available = new Set(records.map(record => record.batch_id));
    checkedIds = new Set([...checkedIds].filter(id => available.has(id)));
    if (selected && !available.has(selected)) selectBatch(records[0]?.batch_id ?? '');
    else if (!selected && records[0]) selectBatch(records[0].batch_id);
  }

  function selectBatch(id: string) {
    if (detailTimer !== undefined) window.clearTimeout(detailTimer);
    selected = id;
    detail = undefined;
    detailEtag = '';
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
      if (ids.includes(selected)) selectBatch('');
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

  onMount(() => {
    refreshList().catch(error => message = userMessage(error));
    const listTimer = window.setInterval(() => refreshList().catch(() => {}), 2500);
    return () => {
      window.clearInterval(listTimer);
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
          {#if terminal(detail.state.kind) && detail.report}<button on:click={exportReport}>导出报告</button>{/if}
          {#if terminal(detail.state.kind)}<button class="danger" on:click={() => confirm('删除这个批次？计算缓存会保留。') && action(`/v1/batches/${selected}`, 'DELETE')}>删除</button>{/if}
        </div>
      </header>
      {#each detail.request.cases as parameter, index}
        {@const progress = detail.cases.find(item => item.case_id === parameter.id)}
        {@const result = progress?.result ?? detail.report?.reports.find(item => item.case.id === parameter.id)}
        <article class="result-card">
          <header>
            <div><p class="eyebrow">第 {index + 1} 组参数</p><h3>{parameter.name}</h3><div class="run-meta"><code>{parameter.id}</code><span class="status {progress?.state.kind ?? 'queued'}">{stateName(progress?.state)}</span></div></div>
            <span class="security-bit">
              {#if result?.summary.security_bits}<small>{terminal(progress?.state.kind) ? '安全' : '当前最低'}</small><strong>{bits(result.summary.security_bits)} bit</strong>{:else}<strong>—</strong>{/if}
            </span>
          </header>
          <ProblemSummary problem={parameter.problem} />
          <p class="case-progress">已返回 {result?.attacks.length ?? 0}/{progress?.expected_attack_count ?? 0} 项攻击</p>
          {#if result?.attacks.length}
            <div class="attack-grid">
              {#each result.attacks as attackResult}
                <div class="attack">
                  <span>{attackResult.attack}</span><strong>{bits(attackResult.outcome.security_bits)}</strong>
                  <small>{outcomeName(attackResult)}</small>
                  {#if attackResult.outcome.code || technicalDetail(attackResult)}
                    <details><summary>技术详情</summary><small>{attackResult.outcome.code ?? ''}{attackResult.outcome.code && technicalDetail(attackResult) ? '：' : ''}{technicalDetail(attackResult)}</small></details>
                  {/if}
                </div>
              {/each}
            </div>
            {#each result.summary.warnings as warning}<p class="warning">{warning}</p>{/each}
            {#if !terminal(progress?.state.kind)}<p class="empty progress-waiting">正在等待其余 Sage 进程返回…</p>{/if}
          {:else}
            <p class="empty">{terminal(progress?.state.kind) ? '这组参数没有生成攻击结果。' : '等待攻击结果…'}</p>
          {/if}
        </article>
      {/each}
    {:else if selected}<div class="empty centered">正在载入批次详情…</div>
    {:else}<div class="empty centered">从左侧选择一个批次查看参数和结果。</div>{/if}
    {#if message}<p class="notice">{message}</p>{/if}
  </section>
</div>
