<!-- Shared normal/rough execution settings used by both scheme editors. -->
<script lang="ts">
  import type { RunSettings } from './runSettings';

  export let settings: RunSettings;
  export let showModeSwitch = false;

  function setMode(mode: RunSettings['mode']) {
    settings = { ...settings, mode };
  }
</script>

{#if showModeSwitch}
  <div class="option-heading">
    <div><strong>运行设置</strong><p class="hint">这些设置用于本次运行，不写入方案参数。</p></div>
    <div class="mode-switch">
      <button class:active={settings.mode === 'rough'} on:click={() => setMode('rough')}>快速</button>
      <button class:active={settings.mode === 'normal'} on:click={() => setMode('normal')}>正常</button>
    </div>
  </div>
{/if}

<div class="form-grid compact">
  <label>超时（秒）<input type="number" min="1" max="7200" bind:value={settings.timeoutSeconds} /></label>
  {#if settings.mode === 'normal'}
    <label>目标安全 bit<input bind:value={settings.requiredSecurityBits} /></label>
  {/if}
</div>
{#if settings.mode === 'normal'}
  <details class="advanced-run-settings">
    <summary>高级运行设置</summary>
    <p class="hint">分别设置各筛选阶段的自定义最低跳过余量；实际值不会低于经校准的安全下限。</p>
    <div class="form-grid advanced-margin-grid">
      <label>Arora-GB 粗筛自定义最低跳过余量<input min="0" type="number" bind:value={settings.aroraGbCoarseMarginBits} /></label>
      <label>Arora-GB 精筛自定义最低跳过余量<input min="0" type="number" bind:value={settings.aroraGbRefinedMarginBits} /></label>
      <label>BKW 自定义最低跳过余量<input min="0" type="number" bind:value={settings.bkwMarginBits} /></label>
    </div>
    <div class="force-options">
      <span><strong>手动运行慢攻击</strong><small>绕过适用域与安全余量判断；可能耗时很久，已有成功结果仍会使用缓存。</small></span>
      <label class="check-option"><input type="checkbox" bind:checked={settings.forceAroraGb} /> 强制 Arora-GB</label>
      <label class="check-option"><input type="checkbox" bind:checked={settings.forceBkw} /> 强制 BKW</label>
    </div>
  </details>
{/if}
