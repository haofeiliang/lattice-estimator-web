<script lang="ts">
  import type { CaseDraft } from './drafts';

  export let draft: CaseDraft;
  export let index: number;
  export let focused = false;
  export let removable = false;
  export let onRemove: () => void = () => {};
</script>

<section class:edit-focus={focused} class="panel case-card" data-estimate-case-id={draft.id} tabindex="-1">
  <header>
    <strong>#{index + 1} {draft.name || '未命名参数'}</strong>
    {#if removable}<button class="danger ghost" on:click={onRemove}>删除</button>{/if}
  </header>
  <div class="case-sections">
    <fieldset class="case-field-group">
      <legend>基本设置</legend>
      <div class="case-fields">
        <label>参数 ID（自动生成）<input bind:value={draft.id} readonly /></label>
        <label>名称<input bind:value={draft.name} /></label>
        <label>问题类型<select bind:value={draft.kind}><option value="lwe">LWE</option><option value="rlwe">RLWE</option><option value="glwe">GLWE</option><option value="ntru">NTRU</option><option value="sis">SIS</option></select></label>
        <label>安全模型<select bind:value={draft.securityModel}><option value="classical">经典</option><option value="quantum">量子</option></select></label>
      </div>
    </fieldset>

    <fieldset class="case-field-group">
      <legend>问题参数</legend>
      <div class="case-fields">
        {#if draft.kind === 'glwe'}<label>GLWE 维数 k<input type="number" min="1" max="65536" bind:value={draft.glweDimension} /></label>{/if}
        {#if draft.kind === 'ntru'}<label>NTRU 结构<select bind:value={draft.ntruStructure}><option value="circulant">多项式（循环矩阵）</option><option value="matrix">一般矩阵</option></select></label>{/if}
        <label>{draft.kind === 'rlwe' || draft.kind === 'glwe' || (draft.kind === 'ntru' && draft.ntruStructure === 'circulant') ? '多项式长度 N' : draft.kind === 'ntru' ? '矩阵维数 n' : '维数 n'}<input type="number" min="1" max="65536" bind:value={draft.dimension} /></label>
        <label>模数 q<input bind:value={draft.modulus} /></label>
        {#if draft.kind === 'sis'}
          <label>列数 m<input type="number" min="1" bind:value={draft.columns} /></label>
          <label>长度界 β<input bind:value={draft.lengthBound} /></label>
          <label>范数<select bind:value={draft.sisNorm}><option value="l2">L2</option><option value="l_infinity">L∞</option></select></label>
        {:else}
          {#if draft.kind !== 'ntru'}<label>样本数<input bind:value={draft.samples} placeholder="输入 unlimited（无限）或整数" /></label>{/if}
        {/if}
      </div>
    </fieldset>

    {#if draft.kind !== 'sis'}
      <fieldset class="case-field-group">
        <legend>私钥分布</legend>
        <div class="distribution-fields">
          <label>分布类型<select bind:value={draft.secretKind}><option value="uniform_binary">均匀二元</option><option value="sparse_ternary">稀疏三元 (1/4, 1/2, 1/4)</option><option value="uniform_ternary">均匀三元</option><option value="fixed_weight_binary">固定重量二元</option><option value="fixed_weight_ternary">固定重量三元</option><option value="discrete_gaussian">离散高斯</option><option value="centered_binomial">中心二项</option><option value="uniform_integer">有界均匀整数</option></select></label>
          {#if draft.secretKind === 'fixed_weight_binary'}<label>汉明重量<input type="number" min="0" bind:value={draft.secretWeight} /></label>{/if}
          {#if draft.secretKind === 'fixed_weight_ternary'}<label>+1 数量<input type="number" min="0" bind:value={draft.secretPositiveWeight} /></label><label>-1 数量<input type="number" min="0" bind:value={draft.secretNegativeWeight} /></label>{/if}
          {#if draft.secretKind === 'discrete_gaussian'}<label>标准差 σ<input bind:value={draft.secretSigma} /></label>{/if}
          {#if draft.secretKind === 'centered_binomial'}<label>参数 η<input type="number" min="1" bind:value={draft.secretEta} /></label>{/if}
          {#if draft.secretKind === 'uniform_integer'}<label>下界<input bind:value={draft.secretLower} /></label><label>上界<input bind:value={draft.secretUpper} /></label>{/if}
        </div>
      </fieldset>

      <fieldset class="case-field-group">
        <legend>噪声分布</legend>
        <div class="distribution-fields">
          <label>分布类型<select bind:value={draft.errorKind}><option value="discrete_gaussian">离散高斯</option><option value="centered_binomial">中心二项</option><option value="uniform_integer">有界均匀整数</option></select></label>
          {#if draft.errorKind === 'discrete_gaussian'}<label>标准差 σ<input bind:value={draft.errorSigma} /></label>{/if}
          {#if draft.errorKind === 'centered_binomial'}<label>参数 η<input type="number" min="1" bind:value={draft.errorEta} /></label>{/if}
          {#if draft.errorKind === 'uniform_integer'}<label>下界<input bind:value={draft.errorLower} /></label><label>上界<input bind:value={draft.errorUpper} /></label>{/if}
        </div>
      </fieldset>
    {/if}
  </div>
  <details class="case-meta">
    <summary>说明与标签</summary>
    <div class="form-grid meta-grid">
      <label class="wide">说明<input bind:value={draft.description} placeholder="可选" /></label>
      <label>标签<input bind:value={draft.tags} placeholder="逗号分隔" /></label>
    </div>
  </details>
</section>
