<script lang="ts">
  import { onMount } from 'svelte';
  import EstimatePanel from './EstimatePanel.svelte';
  import RunsPanel from './RunsPanel.svelte';
  import SchemePanel from './SchemePanel.svelte';
  import { api, getToken, setToken, userMessage } from './api';
  import type { EstimateDraftSource, EstimateRequest } from './types';

  type Tab = 'estimate' | 'schemes' | 'runs';
  const tabPaths: Record<Tab, string> = {
    estimate: '/estimate',
    schemes: '/schemes',
    runs: '/runs',
  };
  function routeFromLocation() {
    const path = window.location.pathname.replace(/\/+$/, '') || '/';
    const tab = (Object.entries(tabPaths).find(([, value]) => value === path)?.[0] ?? 'estimate') as Tab;
    const batchId = tab === 'runs' ? new URLSearchParams(window.location.search).get('batch') ?? '' : '';
    return { tab, batchId, canonical: path === tabPaths[tab] };
  }
  const initialRoute = routeFromLocation();
  let tab: Tab = initialRoute.tab;
  let selectedBatchId = initialRoute.batchId;
  let token = getToken();
  let authenticated = false;
  let checking = true;
  let error = '';
  let metadata: Record<string, unknown> = {};
  let estimateDraftSource: EstimateDraftSource | undefined;
  let editSequence = 0;

  function applyLocation() {
    const route = routeFromLocation();
    tab = route.tab;
    selectedBatchId = route.batchId;
  }

  function navigate(nextTab: Tab, batchId = nextTab === 'runs' ? selectedBatchId : '', replace = false) {
    const url = new URL(window.location.href);
    url.pathname = tabPaths[nextTab];
    url.search = '';
    if (nextTab === 'runs' && batchId) url.searchParams.set('batch', batchId);
    if (url.pathname === window.location.pathname && url.search === window.location.search) {
      applyLocation();
      return;
    }
    window.history[replace ? 'replaceState' : 'pushState']({}, '', url);
    applyLocation();
  }

  function editBatch(request: EstimateRequest, batchId: string, focusCaseId?: string) {
    estimateDraftSource = {
      sequence: ++editSequence,
      batchId,
      request,
      ...(focusCaseId ? { focusCaseId } : {}),
    };
    navigate('estimate');
  }

  onMount(() => {
    if (!initialRoute.canonical || (tab !== 'runs' && window.location.search)) {
      navigate(tab, selectedBatchId, true);
    }
    const handlePopState = () => applyLocation();
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  });

  async function connect() {
    setToken(token); checking = true; error = '';
    try { metadata = await api('/v1/metadata'); authenticated = true; }
    catch (reason) { authenticated = false; error = userMessage(reason); }
    finally { checking = false; }
  }
  connect();
</script>

<header class="app-header">
  <div class="brand"><span class="mark">λ</span><div><strong>格密码安全估算器</strong><small>参数安全估算</small></div></div>
  {#if authenticated}<div class="context"><span>估算器 {String(metadata.estimator_commit ?? '').slice(0, 8)}</span><button class="ghost" on:click={() => { setToken(''); token = ''; authenticated = false; }}>更换令牌</button></div>{/if}
</header>

{#if !authenticated}
  <main class="login-wrap">
    <section class="panel login">
      <p class="eyebrow">连接服务</p><h1>连接安全服务</h1>
      <p>如果服务未配置 API 令牌，直接连接即可；否则输入部署时设置的令牌。令牌只保存在当前浏览器标签页。</p>
      <label>API 令牌<input type="password" bind:value={token} on:keydown={(event) => event.key === 'Enter' && connect()} /></label>
      <button class="primary" disabled={checking} on:click={connect}>{checking ? '连接中…' : '连接'}</button>
      {#if error}<p class="notice error">{error}</p>{/if}
    </section>
  </main>
{:else}
  <nav class="tabs" aria-label="主导航">
    <button class:active={tab === 'estimate'} on:click={() => navigate('estimate')}>安全估算</button>
    <button class:active={tab === 'schemes'} on:click={() => navigate('schemes')}>方案库</button>
    <button class:active={tab === 'runs'} on:click={() => navigate('runs')}>运行批次</button>
  </nav>
  <main class="workspace">
    <div hidden={tab !== 'estimate'}><EstimatePanel editSource={estimateDraftSource} /></div>
    {#if tab === 'schemes'}<SchemePanel />
    {:else if tab === 'runs'}<RunsPanel
      onEditRequest={editBatch}
      {selectedBatchId}
      onSelectionChange={(batchId, replace) => navigate('runs', batchId, replace)}
    />{/if}
  </main>
{/if}
