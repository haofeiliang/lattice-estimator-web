<!-- New-estimate workflow: edit cases, advanced policy, save a scheme, or submit a batch. -->
<script lang="ts">
  import { tick } from 'svelte';
  import CaseEditor from './CaseEditor.svelte';
  import RunOptions from './RunOptions.svelte';
  import { api, userMessage } from './api';
  import { appendFreshDraft, caseFromDraft, draftFromCase, freshDraft, freshIdentifier } from './drafts';
  import { saveParameterSet } from './parameterSets';
  import { buildEstimateRequest, defaultRunSettings, runSettingsFromRequest } from './runSettings';
  import type { CaseDraft } from './drafts';
  import type { EstimateDraftSource, ParameterSet } from './types';

  export let editSource: EstimateDraftSource | undefined;

  let drafts: CaseDraft[] = [freshDraft(1)];
  let runSettings = defaultRunSettings();
  let setId = freshIdentifier('scheme');
  let setName = '新方案';
  let busy = false;
  let message = '';
  let savedSetId = false;
  let setDescription = '';
  let setTags: string[] = [];
  let sourceBatchId = '';
  let focusedCaseId = '';
  let loadedEditSequence = 0;

  $: if (editSource && editSource.sequence !== loadedEditSequence) {
    loadedEditSequence = editSource.sequence;
    void loadFromBatch(editSource);
  }

  async function loadFromBatch(source: EstimateDraftSource) {
    const value = source.request;
    drafts = value.cases.map(draftFromCase);
    runSettings = runSettingsFromRequest(value);
    setName = value.name?.trim() || '新方案';
    sourceBatchId = source.batchId;
    focusedCaseId = source.focusCaseId ?? '';
    setDescription = '';
    setTags = [];
    message = `已载入批次 ${source.batchId} 的参数副本；原批次不会改变`;

    if (value.parameter_set_id) {
      setId = value.parameter_set_id;
      savedSetId = true;
      try {
        const parameterSet = await api<ParameterSet>(`/v1/parameter-sets/${encodeURIComponent(value.parameter_set_id)}`);
        if (loadedEditSequence !== source.sequence) return;
        setDescription = parameterSet.description ?? '';
        setTags = [...(parameterSet.tags ?? [])];
      } catch {
        if (loadedEditSequence !== source.sequence) return;
        setId = freshIdentifier('scheme');
        savedSetId = false;
        message = `已载入批次 ${source.batchId}；关联方案不可用，保存时将创建新方案`;
      }
    } else {
      setId = freshIdentifier('scheme');
      savedSetId = false;
    }

    await tick();
    if (loadedEditSequence !== source.sequence || !focusedCaseId) return;
    const target = Array.from(document.querySelectorAll<HTMLElement>('[data-estimate-case-id]'))
      .find(element => element.dataset.estimateCaseId === focusedCaseId);
    target?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    target?.focus({ preventScroll: true });
  }

  async function run() {
    busy = true; message = '';
    try {
      const request = buildEstimateRequest({
        name: setName,
        ...(savedSetId ? { parameterSetId: setId } : {}),
        cases: drafts.map(caseFromDraft),
        settings: runSettings,
      });
      const result = await api<{ batch_id: string }>('/v1/estimates', { method: 'POST', body: JSON.stringify(request) });
      message = `已创建批次 ${result.batch_id}`;
    } catch (error) { message = userMessage(error); }
    finally { busy = false; }
  }

  async function save() {
    busy = true; message = '';
    try {
      const value: ParameterSet = {
        format: 'lattice-estimator/parameter-set', version: 2, id: setId, name: setName,
        ...(setDescription.trim() ? { description: setDescription.trim() } : {}),
        tags: setTags, cases: drafts.map(caseFromDraft)
      };
      const saved = await saveParameterSet(value, {
        replace: savedSetId,
        regenerateIdOnConflict: !savedSetId,
      });
      setId = saved.id;
      savedSetId = true;
      message = `方案 ${setId} 已保存`;
    } catch (error) { message = userMessage(error); }
    finally { busy = false; }
  }

  async function saveAs() {
    setId = freshIdentifier('scheme');
    savedSetId = false;
    await save();
  }
</script>

<section class="panel intro">
  <div>
    <p class="eyebrow">安全估算</p>
    <h2>直接输入多组参数</h2>
    <p>快速模式只运行 primal/BDD 与 dual；正常模式会先运行快速攻击，再按适用范围和安全余量决定是否运行 Arora-GB、BKW。</p>
  </div>
  <div class="mode-switch" aria-label="估算模式">
    <button class:active={runSettings.mode === 'rough'} on:click={() => runSettings = { ...runSettings, mode: 'rough' }}>快速</button>
    <button class:active={runSettings.mode === 'normal'} on:click={() => runSettings = { ...runSettings, mode: 'normal' }}>正常</button>
  </div>
</section>

{#if sourceBatchId}
  <section class="edit-source-notice" aria-label="批次参数副本">
    <div><strong>正在修改历史批次的参数副本</strong><span>原批次 <code>{sourceBatchId}</code> 不会改变；未修改的参数和攻击仍可复用缓存。</span></div>
    {#if focusedCaseId}<span class="focus-label">已定位所选参数</span>{/if}
  </section>
{/if}

<section class="panel estimate-scheme-meta">
  <div class="option-heading">
    <div><p class="eyebrow">方案信息</p><p class="hint">方案 ID 自动生成并保持稳定；名称可随方案版本调整。</p></div>
    <div class="actions top-editor-actions">
      {#if sourceBatchId && savedSetId}<button disabled={busy} on:click={saveAs}>另存为新方案</button>{/if}
      <button class="secondary" disabled={busy} on:click={save}>{savedSetId ? '保存方案新版本' : '保存为方案'}</button>
      <button class="primary" disabled={busy} on:click={run}>{busy ? '处理中…' : '开始估算'}</button>
    </div>
  </div>
  <div class="form-grid scheme-identity-grid">
    <label>方案 ID（自动生成）<input bind:value={setId} readonly /></label>
    <label>方案名称<input bind:value={setName} /></label>
  </div>
  {#if message}<p class="notice">{message}</p>{/if}
</section>

<div class="case-list">
  {#each drafts as draft, index}
    <CaseEditor
      {draft}
      {index}
      focused={focusedCaseId === draft.id}
      removable={drafts.length > 1}
      onRemove={() => drafts = drafts.filter((_, itemIndex) => itemIndex !== index)}
    />
  {/each}
</div>

<button class="add-case" on:click={() => drafts = appendFreshDraft(drafts)}>＋ 添加一组参数</button>

<section class="panel run-options">
  <RunOptions bind:settings={runSettings} />
  <div class="actions">
    {#if sourceBatchId && savedSetId}<button disabled={busy} on:click={saveAs}>另存为新方案</button>{/if}
    <button class="secondary" disabled={busy} on:click={save}>{savedSetId ? '保存方案新版本' : '保存为方案'}</button>
    <button class="primary" disabled={busy} on:click={run}>{busy ? '处理中…' : '开始估算'}</button>
  </div>
  {#if message}<p class="notice">{message}</p>{/if}
</section>
