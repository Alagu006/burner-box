<script>
  let { open = $bindable(false) } = $props();

  const shortcuts = [
    { keys: ['Ctrl', 'K'], description: 'Open command palette' },
    { keys: ['Ctrl', '/'], description: 'Show this help' },
    { keys: ['Esc'], description: 'Close overlays / Quick exit in rooms' },
    { keys: ['Enter'], description: 'Send message (in rooms)' },
  ];
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="shortcuts-overlay-backdrop"
  onclick={() => { open = false; }}
  onkeydown={(e) => { if (e.key === 'Escape') open = false; }}
>
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md bg-slate-800 border border-slate-600 rounded-xl shadow-2xl z-[9998] p-6"
    onclick={(e) => e.stopPropagation()}
    onkeydown={(e) => { if (e.key === 'Escape') open = false; }}
    role="dialog"
    aria-label="Keyboard shortcuts"
    tabindex="-1"
  >
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-lg font-bold text-white">Keyboard Shortcuts</h2>
      <button
        onclick={() => { open = false; }}
        class="text-slate-400 hover:text-white text-lg cursor-pointer"
        aria-label="Close shortcuts help"
      >✕</button>
    </div>

    <div class="space-y-3">
      {#each shortcuts as shortcut}
        <div class="flex items-center justify-between">
          <span class="text-slate-300 text-sm">{shortcut.description}</span>
          <div class="flex gap-1">
            {#each shortcut.keys as key}
              <kbd class="bg-slate-700 border border-slate-600 text-white text-xs px-2 py-1 rounded font-mono">{key}</kbd>
            {/each}
          </div>
        </div>
      {/each}
    </div>

    <p class="text-slate-500 text-xs mt-6 pt-4 border-t border-slate-700">
      Press <kbd class="bg-slate-700 px-1 py-0.5 rounded text-[10px]">Ctrl+K</kbd> to quickly navigate to any page.
    </p>
  </div>
</div>
