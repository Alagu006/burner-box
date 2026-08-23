<script>
	import favicon from '$lib/assets/favicon.svg';
	import '../app.css';
	import { theme } from '$lib/theme';
	import CommandPalette from '$lib/components/CommandPalette.svelte';
	import ShortcutsHelp from '$lib/components/ShortcutsHelp.svelte';
	import LanguageSwitcher from '$lib/components/LanguageSwitcher.svelte';

	let { children } = $props();
	let showPalette = $state(false);
	let showHelp = $state(false);

	function handleGlobalKeydown(e) {
		// Ctrl+K or Cmd+K — command palette
		if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
			e.preventDefault();
			showPalette = !showPalette;
		}
		// Ctrl+/ — shortcuts help
		if ((e.ctrlKey || e.metaKey) && e.key === '/') {
			e.preventDefault();
			showHelp = !showHelp;
		}
		// Escape closes overlays
		if (e.key === 'Escape') {
			showPalette = false;
			showHelp = false;
		}
	}

	function toggleTheme() {
		theme.toggle();
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<svelte:window onkeydown={handleGlobalKeydown} />

<!-- Top toolbar (fixed position) -->
<div class="fixed top-3 left-3 right-3 z-50 flex items-center gap-2 pointer-events-none">
	<button
		onclick={toggleTheme}
		class="pointer-events-auto bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm cursor-pointer transition"
		aria-label="Toggle light/dark theme"
	>
		{#if $theme === 'dark'}
			☀️
		{:else}
			🌙
		{/if}
	</button>
	<div class="pointer-events-auto">
		<LanguageSwitcher />
	</div>
</div>

<!-- Command palette -->
{#if showPalette}
	<CommandPalette bind:open={showPalette} />
{/if}

<!-- Shortcuts help -->
{#if showHelp}
	<ShortcutsHelp bind:open={showHelp} />
{/if}

{@render children()}
