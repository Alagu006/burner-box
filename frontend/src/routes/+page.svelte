<script>
  import { API_URL } from '$lib/api';

  let apiStatus = $state('Checking...');
  let apiConnected = $state(false);
  let checkCount = $state(0);

  $effect(() => {
    checkBackend();
  });

  async function checkBackend() {
    try {
      const response = await fetch(`${API_URL}/api/health`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        apiStatus = data.message || 'Connected';
        apiConnected = true;
      } else {
        apiStatus = 'Backend returned error: ' + response.status;
        apiConnected = false;
      }
    } catch (err) {
      apiStatus = 'Backend not reachable. Is it running on :8080?';
      apiConnected = false;
    }
  }

  function retryCheck() {
    apiStatus = 'Checking...';
    apiConnected = false;
    checkBackend();
  }
</script>

<div class="min-h-screen flex flex-col items-center justify-center p-4">
  
  <!-- Title -->
  <div class="text-center mb-8">
    <h1 class="text-5xl font-bold text-emerald-500 mb-2">
      🔥 BurnerBox
    </h1>
    <p class="text-xl text-slate-400">
      Secure. Anonymous. Ephemeral.
    </p>
  </div>

  <!-- Status Card -->
  <div class="bg-slate-800 rounded-lg p-6 max-w-md w-full shadow-xl">
    <h2 class="text-lg font-semibold mb-4 border-b border-slate-700 pb-2">
      System Status
    </h2>

    <div class="space-y-3">
      <div class="flex justify-between items-center">
        <span class="text-slate-300">Frontend</span>
        <span class="text-emerald-500">✅ Running</span>
      </div>

      <div class="flex justify-between items-center">
        <span class="text-slate-300">Backend API</span>
        {#if apiConnected}
          <span class="text-emerald-500">✅ Connected</span>
        {:else}
          <span class="text-red-500">❌ {apiStatus}</span>
        {/if}
      </div>

      <div class="flex justify-between items-center">
        <span class="text-slate-300">Encryption</span>
        <span class="text-emerald-500">🔒 Ready</span>
      </div>
    </div>

    {#if !apiConnected}
      <button
        onclick={retryCheck}
        class="mt-4 w-full bg-slate-700 hover:bg-slate-600 text-white py-2 rounded-lg text-sm transition cursor-pointer"
      >
        🔄 Retry Connection
      </button>
    {/if}
  </div>

  <!-- Navigation -->
  <div class="mt-8 flex gap-4 flex-wrap justify-center">
    <a href="/submit" 
       class="bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-3 rounded-lg font-medium transition no-underline">
      📨 Submit Tip
    </a>
    <a href="/room/create" 
       class="bg-slate-700 hover:bg-slate-600 text-white px-6 py-3 rounded-lg font-medium transition no-underline">
      💬 Create Room
    </a>
  </div>

  <div class="mt-4 flex gap-4 flex-wrap justify-center">
    <a href="/login" 
       class="text-slate-400 hover:text-white px-4 py-2 transition no-underline text-sm">
      🔐 Organization Login
    </a>
    <a href="/signup" 
       class="text-slate-400 hover:text-white px-4 py-2 transition no-underline text-sm">
      🚀 Register Organization
    </a>
    <a href="/check-replies" 
       class="text-slate-400 hover:text-white px-4 py-2 transition no-underline text-sm">
      📬 Check Replies
    </a>
  </div>

  <!-- Footer -->
  <p class="mt-12 text-slate-600 text-sm">
    No cookies. No tracking. Open source.
  </p>
</div>