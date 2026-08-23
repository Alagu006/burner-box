<script>
  import { locale, getLanguages } from '$lib/i18n.js';

  const languages = getLanguages();
  let open = $state(false);

  function select(lang) {
    locale.set(lang);
    open = false;
  }
</script>

<div class="relative">
  <button
    onclick={() => { open = !open; }}
    class="bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm cursor-pointer transition flex items-center gap-2"
    aria-label="Change language"
    aria-expanded={open}
  >
    🌐 {languages.find(l => l.code === $locale)?.name || 'English'}
  </button>

  {#if open}
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div
      class="absolute right-0 mt-1 bg-slate-800 border border-slate-600 rounded-lg shadow-xl z-50 min-w-[140px]"
      onkeydown={(e) => { if (e.key === 'Escape') open = false; }}
      role="menu"
      aria-label="Language selection"
      tabindex="-1"
    >
      {#each languages as lang}
        <button
          onclick={() => select(lang.code)}
          class="w-full text-left px-3 py-2 text-sm cursor-pointer transition
            {lang.code === $locale ? 'text-emerald-400 bg-slate-700' : 'text-slate-300 hover:bg-slate-700'}"
        >
          {lang.name}
        </button>
      {/each}
    </div>
  {/if}
</div>
