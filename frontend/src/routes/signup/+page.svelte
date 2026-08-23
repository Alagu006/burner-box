<script>
  import { generateKeyPair, encryptPrivateKey, cacheDerivedKey } from '$lib/crypto';
  import { API_URL } from '$lib/api';

  // Svelte 5 Runes
  let name = $state('');
  let email = $state('');
  let password = $state('');
  let confirmPassword = $state('');
  let error = $state('');
  let loading = $state(false);
  let success = $state(false);
  let submissionUrl = $state('');
  let countdown = $state(5);
  let redirectTimer = null;
  let generatingKeys = $state(false);

  // Svelte 5 cleanup using $effect
  $effect(() => {
    return () => {
      if (redirectTimer) {
        clearInterval(redirectTimer);
      }
    };
  });

  function startRedirectCountdown() {
    redirectTimer = setInterval(() => {
      countdown -= 1;
      if (countdown <= 0) {
        clearInterval(redirectTimer);
        window.location.href = '/login';
      }
    }, 1000);
  }

  async function handleSignup(e) {
    if (e) e.preventDefault();
    error = '';

    if (password !== confirmPassword) {
      error = 'Passwords do not match';
      return;
    }
    if (password.length < 8) {
      error = 'Password must be at least 8 characters';
      return;
    }

    loading = true;
    generatingKeys = true;

    try {
      // Generate E2EE key pair in browser
      const keyPair = await generateKeyPair();
      
      // Derive a key from the signup password and encrypt the private key
      // before storing in localStorage. This prevents plaintext key exposure
      // on disk (XSS/browser extension theft).
      const encResult = await encryptPrivateKey(keyPair.privateKey, password);
      localStorage.setItem('burnerbox_private_key', JSON.stringify({
        encrypted: encResult.encryptedPrivateKey,
        salt: encResult.salt,
        nonce: encResult.nonce,
      }));
      // Cache derived key for the current session
      const s = await import('libsodium-wrappers');
      await s.default.ready;
      const derivedKey = await (await import('$lib/crypto')).deriveKeyFromPassword(
        password, encResult.salt
      );
      cacheDerivedKey(derivedKey);
      
        const response = await fetch(`${API_URL}/api/v1/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          name, 
          email, 
          password,
          public_key: keyPair.publicKey 
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        // If signup fails, remove the private key
        localStorage.removeItem('burnerbox_private_key');
        error = data.error || 'Signup failed';
        loading = false;
        generatingKeys = false;
        return;
      }

      const slug = data.organization.submission_slug;
      submissionUrl = `${window.location.origin}/submit/${slug}`;
      success = true;
      startRedirectCountdown();

    } catch (err) {
      localStorage.removeItem('burnerbox_private_key');
      error = 'Network error or encryption failed. Is the backend running?';
    }

    loading = false;
    generatingKeys = false;
  }
</script>

<div class="min-h-screen flex items-center justify-center p-4">
  <div class="bg-slate-800 rounded-lg p-8 max-w-md w-full shadow-xl">
    
    <div class="text-center mb-6">
      <h1 class="text-3xl font-bold text-emerald-500">🔥 BurnerBox</h1>
      <p class="text-slate-400 mt-2">Register Your Organization</p>
    </div>

    {#if success}
      <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-4">
        <p class="text-emerald-400 text-lg font-bold mb-2">✅ Registration Successful!</p>
        <p class="text-slate-300 text-sm mb-4">
          Share this secret URL with sources to receive anonymous tips:
        </p>
        <div class="bg-slate-900 rounded p-3 mb-4">
          <code class="text-emerald-400 text-sm break-all">{submissionUrl}</code>
        </div>
        <button
          onclick={() => {
            navigator.clipboard.writeText(submissionUrl);
          }}
          class="w-full bg-slate-700 hover:bg-slate-600 text-white py-2 rounded-lg text-sm transition mb-3"
        >
          📋 Copy URL
        </button>
        
        <div class="bg-slate-700 rounded p-2 mb-3 text-center">
          <p class="text-slate-300 text-xs">
            ⏳ Redirecting to login in <span class="text-emerald-400 font-bold">{countdown}</span> seconds...
          </p>
        </div>

        <div class="bg-yellow-900/50 border border-yellow-500 rounded p-2 mb-3">
          <p class="text-yellow-400 text-xs">
            ⚠️ Your encryption key is stored in this browser. Don't clear browser data or you'll lose access to encrypted submissions.
          </p>
        </div>

        <a
          href="/login"
          class="block w-full text-center bg-emerald-600 hover:bg-emerald-700 text-white py-2 rounded-lg font-medium transition no-underline"
        >
          🔐 Go to Login Now →
        </a>
      </div>
    {:else}
      <form onsubmit={handleSignup}>
        
        {#if error}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{error}</p>
          </div>
        {/if}

        <div class="mb-4">
          <label for="name" class="block text-sm font-medium text-slate-300 mb-1">
            Organization Name
          </label>
          <input
            id="name"
            type="text"
            bind:value={name}
            required
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            placeholder="The Daily News"
          />
        </div>

        <div class="mb-4">
          <label for="email" class="block text-sm font-medium text-slate-300 mb-1">
            Email
          </label>
          <input
            id="email"
            type="email"
            bind:value={email}
            required
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            placeholder="org@example.com"
          />
        </div>

        <div class="mb-4">
          <label for="password" class="block text-sm font-medium text-slate-300 mb-1">
            Password
          </label>
          <input
            id="password"
            type="password"
            bind:value={password}
            required
            minlength="8"
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            placeholder="Min. 8 characters"
          />
        </div>

        <div class="mb-6">
          <label for="confirmPassword" class="block text-sm font-medium text-slate-300 mb-1">
            Confirm Password
          </label>
          <input
            id="confirmPassword"
            type="password"
            bind:value={confirmPassword}
            required
            minlength="8"
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            placeholder="Repeat password"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          class="w-full bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white py-2 rounded-lg font-medium transition cursor-pointer"
        >
          {#if loading}
            {generatingKeys ? '🔐 Generating Encryption Keys...' : 'Creating Account...'}
          {:else}
            🚀 Register Organization
          {/if}
        </button>
      </form>

      <p class="text-center text-slate-400 text-sm mt-6">
        Already registered?
        <a href="/login" class="text-emerald-500 hover:underline ml-1">Log in</a>
      </p>
    {/if}
  </div>
</div>