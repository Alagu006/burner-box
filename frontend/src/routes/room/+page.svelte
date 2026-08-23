<script>
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';

  onMount(() => {
    goto('/room/create', { replaceState: true });
  });
</script>

<div class="min-h-screen flex items-center justify-center p-4">
  <div class="text-center">
    <p class="text-slate-400">Redirecting to room creation...</p>
    <a href="/room/create" class="mt-4 inline-block text-emerald-500 hover:underline">← Go to Room Creation</a>
  </div>
</div>
