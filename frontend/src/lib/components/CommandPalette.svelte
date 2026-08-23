<script>
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';

  let { open = $bindable(false) } = $props();
  let query = $state('');
  let inputEl = $state();
  let selectedIndex = $state(0);

  const commands = [
    { label: 'Dashboard', path: '/dashboard', icon: '🏠', category: 'Navigation' },
    { label: 'Submissions', path: '/dashboard/submissions', icon: '📋', category: 'Navigation' },
    { label: 'Security Settings', path: '/dashboard/security', icon: '🔐', category: 'Navigation' },
    { label: 'Team Management', path: '/dashboard/team', icon: '👥', category: 'Navigation' },
    { label: 'Create Room', path: '/room/create', icon: '💬', category: 'Navigation' },
    { label: 'Check Replies', path: '/check-replies', icon: '🔍', category: 'Navigation' },
    { label: 'Login', path: '/login', icon: '🔑', category: 'Account' },
    { label: 'Sign Up', path: '/signup', icon: '📝', category: 'Account' },
  ];

  let filtered = $derived(
    query
      ? commands.filter(c =>
          c.label.toLowerCase().includes(query.toLowerCase()) ||
          c.path.toLowerCase().includes(query.toLowerCase())
        )
      : commands
  );

  onMount(() => {
    if (inputEl) inputEl.focus();
  });

  function selectCommand(cmd) {
    open = false;
    goto(cmd.path);
  }

  function handleKeydown(e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      selectedIndex = Math.min(selectedIndex + 1, filtered.length - 1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      selectedIndex = Math.max(selectedIndex - 1, 0);
    } else if (e.key === 'Enter' && filtered[selectedIndex]) {
      selectCommand(filtered[selectedIndex]);
    } else if (e.key === 'Escape') {
      open = false;
    }
  }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="cmd-palette-backdrop" onclick={() => { open = false; }} onkeydown={(e) => { if (e.key === 'Escape') open = false; }}>
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="fixed top-[15%] left-1/2 -translate-x-1/2 w-full max-w-lg bg-slate-800 border border-slate-600 rounded-xl shadow-2xl z-[9999]"
    onclick={(e) => e.stopPropagation()}
    onkeydown={(e) => { e.stopPropagation(); handleKeydown(e); }}
    role="dialog"
    aria-modal="true"
    aria-label="Command palette"
    tabindex="-1"
  >
    <!-- Search input -->
    <div class="flex items-center gap-3 px-4 py-3 border-b border-slate-700">
      <span class="text-slate-400 text-lg">🔍</span>
      <input
        bind:this={inputEl}
        type="text"
        bind:value={query}
        placeholder="Type a command or search..."
        class="flex-1 bg-transparent text-white text-sm placeholder-slate-500 focus:outline-none"
        onkeydown={handleKeydown}
      />
      <kbd class="text-[10px] text-slate-500 bg-slate-700 px-1.5 py-0.5 rounded">ESC</kbd>
    </div>

    <!-- Results -->
    <div class="max-h-80 overflow-y-auto p-2">
      {#if filtered.length === 0}
        <p class="text-slate-500 text-sm text-center py-8">No commands found</p>
      {:else}
        {#each filtered as cmd, i}
          <button
            onclick={() => selectCommand(cmd)}
            class="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left cursor-pointer transition
              {i === selectedIndex ? 'bg-emerald-600/20 border border-emerald-500/30' : 'hover:bg-slate-700 border border-transparent'}"
          >
            <span class="text-lg">{cmd.icon}</span>
            <div class="flex-1 min-w-0">
              <p class="text-white text-sm font-medium">{cmd.label}</p>
              <p class="text-slate-500 text-xs truncate">{cmd.path}</p>
            </div>
            <span class="text-slate-600 text-xs">{cmd.category}</span>
          </button>
        {/each}
      {/if}
    </div>

    <!-- Footer hint -->
    <div class="px-4 py-2 border-t border-slate-700 flex items-center gap-4 text-xs text-slate-500">
      <span><kbd class="bg-slate-700 px-1 py-0.5 rounded text-[10px]">↑↓</kbd> navigate</span>
      <span><kbd class="bg-slate-700 px-1 py-0.5 rounded text-[10px]">↵</kbd> select</span>
      <span><kbd class="bg-slate-700 px-1 py-0.5 rounded text-[10px]">esc</kbd> close</span>
    </div>
  </div>
</div>
