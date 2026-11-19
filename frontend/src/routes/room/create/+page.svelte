<script>
  import { generateRoomKey } from '$lib/crypto';
  import { API_URL } from '$lib/api';

  let password = $state('');
  let usePassword = $state(false);
  let expiryDuration = $state('24h');
  let loading = $state(false);
  let error = $state('');
  let roomCode = $state('');
  let roomKey = $state('');
  let shareURL = $state('');
  let linkCopied = $state(false);
  let expiryLabel = $state('');

  const expiryOptions = [
    { value: '1h', label: '1 hour' },
    { value: '6h', label: '6 hours' },
    { value: '24h', label: '24 hours' },
    { value: '72h', label: '3 days' },
    { value: '168h', label: '7 days (max)' },
  ];

  function handleQuickExit() {
    window.location.replace('https://www.weather.com');
  }

  async function handleCreate(e) {
    e.preventDefault();
    error = '';
    loading = true;
    linkCopied = false;

    try {
      // Generate symmetric room key in the browser (never sent to server)
      roomKey = await generateRoomKey();

      const body = {
        expiry_duration: expiryDuration,
      };
      if (usePassword && password) {
        body.password = password;
      }

      const response = await fetch(`${API_URL}/api/v1/rooms/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await response.json();
      if (!response.ok) {
        error = data.error || 'Failed to create room';
        loading = false;
        return;
      }

      roomCode = data.room_code;

      if (data.creator_token) {
        try {
          sessionStorage.setItem('bb_creator_token_' + data.room_code, data.creator_token);
        } catch (e) {
          console.warn('Unable to persist creator token in sessionStorage', e);
        }
      }

      // Build share URL with encryption key in the fragment
      // Fragment is NEVER sent to the server
      const base = window.location.origin + '/room/' + roomCode;
      shareURL = base + '#key=' + roomKey;

      expiryLabel = new Date(data.expires_at).toLocaleString();
    } catch (err) {
      error = 'Cannot reach server. Is the backend running?';
    }
    loading = false;
  }

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(shareURL);
      linkCopied = true;
      setTimeout(() => { linkCopied = false; }, 3000);
    } catch {
      // Fallback: select the text
      const el = document.getElementById('share-link');
      if (el) { el.select(); document.execCommand('copy'); }
      linkCopied = true;
      setTimeout(() => { linkCopied = false; }, 3000);
    }
  }
</script>

<svelte:head>
  <title>Create Secure Room - BurnerBox</title>
</svelte:head>

<div class="min-h-screen bg-slate-900 p-4">

  <!-- Quick Exit Button -->
  <div class="fixed top-4 right-4 z-50">
    <button
      onclick={handleQuickExit}
      class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-bold text-sm transition cursor-pointer shadow-lg"
    >
      ⚡ QUICK EXIT
    </button>
  </div>

  <div class="max-w-xl mx-auto pt-16">

    {#if roomCode}
      <!-- Room Created — Show Share Link -->
      <div class="bg-slate-800 rounded-lg p-8 shadow-xl">
        <div class="text-center mb-6">
          <h1 class="text-2xl font-bold text-emerald-500 mb-2">Room Created</h1>
          <p class="text-slate-400 text-sm">
            Share this link with anyone who should join.
          </p>
        </div>

        <!-- Share Link -->
        <div class="mb-6">
          <label for="share-link" class="block text-sm font-medium text-slate-300 mb-2">
            Encrypted Share Link
          </label>
          <div class="flex gap-2">
            <input
              id="share-link"
              type="text"
              readonly
              value={shareURL}
              class="flex-1 px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-emerald-400 text-sm font-mono"
            />
            <button
              onclick={copyLink}
              class="px-4 py-3 rounded-lg font-medium transition cursor-pointer text-sm shrink-0
                {linkCopied ? 'bg-emerald-600 text-white' : 'bg-slate-700 hover:bg-slate-600 text-white'}"
            >
              {linkCopied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <p class="text-slate-500 text-xs mt-2">
            The encryption key is embedded after the # symbol. It never leaves your browser.
          </p>
        </div>

        <!-- Room Details -->
        <div class="bg-slate-700/50 rounded-lg p-4 mb-6 space-y-2">
          <div class="flex justify-between">
            <span class="text-slate-400 text-sm">Room Code</span>
            <span class="text-white font-mono text-sm">{roomCode}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400 text-sm">Password Protected</span>
            <span class="text-white text-sm">{usePassword ? 'Yes' : 'No'}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400 text-sm">Expires</span>
            <span class="text-white text-sm">{expiryLabel}</span>
          </div>
        </div>

        <!-- Warning -->
        <div class="bg-yellow-900/30 border border-yellow-700 rounded-lg p-4 mb-6">
          <p class="text-yellow-400 text-sm">
            Anyone with this link can join the room and read messages. Share it only with trusted parties.
          </p>
        </div>

        <div class="flex gap-3">
          <a
            href="/room/{roomCode}#key={roomKey}"
            class="flex-1 bg-emerald-600 hover:bg-emerald-700 text-white py-3 rounded-lg font-medium transition text-center no-underline"
          >
            Enter Room
          </a>
          <a
            href="/"
            class="bg-slate-700 hover:bg-slate-600 text-white px-6 py-3 rounded-lg font-medium transition text-center no-underline"
          >
            Home
          </a>
        </div>
      </div>

    {:else}
      <!-- Create Room Form -->
      <div class="bg-slate-800 rounded-lg p-8 shadow-xl">
        <div class="text-center mb-6">
          <h1 class="text-2xl font-bold text-white">💬 Create Secure Room</h1>
          <p class="text-slate-400 text-sm mt-2">
            Ephemeral, encrypted chat. Messages never leave your browser in plaintext.
          </p>
        </div>

        {#if error}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{error}</p>
          </div>
        {/if}

        <form onsubmit={handleCreate}>
          <!-- Expiry Duration -->
          <div class="mb-4">
            <label for="expiry" class="block text-sm font-medium text-slate-300 mb-2">
              Room Lifetime
            </label>
            <select
              id="expiry"
              bind:value={expiryDuration}
              class="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-emerald-500"
            >
              {#each expiryOptions as opt}
                <option value={opt.value}>{opt.label}</option>
              {/each}
            </select>
            <p class="text-slate-500 text-xs mt-1">
              Room and all messages are hard-deleted when this timer expires.
            </p>
          </div>

          <!-- Password Protection -->
          <div class="mb-6">
            <label class="flex items-center gap-3 cursor-pointer mb-2">
              <input
                type="checkbox"
                bind:checked={usePassword}
                class="w-4 h-4 rounded bg-slate-700 border-slate-600 text-emerald-500 focus:ring-emerald-500"
              />
              <span class="text-slate-300 text-sm">Password protect this room</span>
            </label>
            {#if usePassword}
              <input
                type="password"
                bind:value={password}
                placeholder="Room password"
                minlength="1"
                class="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
              />
              <p class="text-slate-500 text-xs mt-1">
                You must share this password separately from the link.
              </p>
            {/if}
          </div>

          <!-- Submit -->
          <button
            type="submit"
            disabled={loading || (usePassword && !password)}
            class="w-full bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white py-3 rounded-lg font-medium transition cursor-pointer"
          >
            {#if loading}
              Creating room...
            {:else}
              Create Room
            {/if}
          </button>
        </form>

        <!-- Security Note -->
        <div class="mt-6 p-4 bg-slate-700/50 rounded-lg">
          <p class="text-slate-400 text-xs">
            A random encryption key is generated in your browser and embedded in the share link.
            The server never receives the key. Only people with the link can decrypt messages.
          </p>
        </div>
      </div>
    {/if}
  </div>
</div>
