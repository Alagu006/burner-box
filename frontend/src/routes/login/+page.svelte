<script>
  import { API_URL } from '$lib/api';
  import { deriveKeyFromPassword, cacheDerivedKey } from '$lib/crypto';
  import { t } from '$lib/i18n';

  let email = $state('');
  let password = $state('');
  let totpCode = $state('');
  let error = $state('');
  let loading = $state(false);
  let success = $state(false);
  let requires2FA = $state(false);
  let pendingToken = $state('');
  let deletedNotice = $state(false);

  $effect(() => {
    if (typeof window !== 'undefined' && window.location.search.includes('deleted=true')) {
      deletedNotice = true;
    }
  });

  async function handleLogin(e) {
    if (e) e.preventDefault();
    error = '';
    loading = true;

    try {
      const response = await fetch(`${API_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        error = data.error || 'Login failed';
        loading = false;
        return;
      }

      if (data.requires_2fa) {
        pendingToken = data.pending_token;
        requires2FA = true;
        loading = false;
        return;
      }

      localStorage.setItem('burnerbox_token', data.token);
      localStorage.setItem('burnerbox_org', JSON.stringify(data.organization));

      // Derive and cache encryption key from login password so the dashboard
      // can decrypt the stored private key. This key lives in JS memory only
      // and is lost when the tab closes.
      try {
        const storedKey = localStorage.getItem('burnerbox_private_key');
        if (storedKey) {
          const parsed = JSON.parse(storedKey);
          if (parsed.salt) {
            const derivedKey = await deriveKeyFromPassword(password, parsed.salt);
            cacheDerivedKey(derivedKey);
          }
        }
      } catch { /* no encrypted key stored yet, or wrong format */ }
      
      success = true;
      
      setTimeout(() => {
        window.location.href = '/dashboard';
      }, 1000);

    } catch (err) {
      error = 'Network error. Is the backend running?';
      loading = false;
    }
  }

  async function handleVerify2FA(e) {
    if (e) e.preventDefault();
    error = '';
    loading = true;

    try {
        const response = await fetch(`${API_URL}/api/v1/auth/login/2fa`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pending_token: pendingToken, code: totpCode }),
      });

      const data = await response.json();

      if (!response.ok) {
        error = data.error || 'Verification failed';
        loading = false;
        return;
      }

      localStorage.setItem('burnerbox_token', data.token);
      localStorage.setItem('burnerbox_org', JSON.stringify(data.organization));

      // Cache derived encryption key (same as non-2FA flow)
      try {
        const storedKey = localStorage.getItem('burnerbox_private_key');
        if (storedKey && password) {
          const parsed = JSON.parse(storedKey);
          if (parsed.salt) {
            const derivedKey = await deriveKeyFromPassword(password, parsed.salt);
            cacheDerivedKey(derivedKey);
          }
        }
      } catch { /* no encrypted key stored yet */ }
      
      success = true;
      
      setTimeout(() => {
        window.location.href = '/dashboard';
      }, 1000);

    } catch (err) {
      error = 'Network error. Is the backend running?';
      loading = false;
    }
  }
</script>

<div class="min-h-screen flex items-center justify-center p-4">
  <div class="bg-slate-800 rounded-lg p-8 max-w-md w-full shadow-xl">
    
    <div class="text-center mb-6">
      <h1 class="text-3xl font-bold text-emerald-500">🔥 BurnerBox</h1>
      <p class="text-slate-400 mt-2">{$t('auth.login_title')}</p>
    </div>

    {#if deletedNotice}
      <div class="bg-red-950/60 border border-red-600 rounded-lg p-4 mb-6 text-center">
        <p class="text-red-300 font-semibold text-sm">Organization account permanently deleted.</p>
        <p class="text-slate-400 text-xs mt-1">All data, submissions, attachments, and keys have been wiped.</p>
      </div>
    {/if}

    {#if success}
      <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-4 text-center">
        <p class="text-emerald-400 text-lg">{$t('auth.login_success')}</p>
        <p class="text-slate-400 text-sm mt-1">{$t('auth.redirecting')}</p>
      </div>
    {:else if requires2FA}
      <form onsubmit={handleVerify2FA}>
        
        {#if error}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{error}</p>
          </div>
        {/if}

        <div class="bg-slate-700/50 border border-slate-600 rounded-lg p-4 mb-4">
          <p class="text-slate-300 text-sm">{$t('auth.2fa_prompt')}</p>
        </div>

        <div class="mb-6">
          <label for="totp" class="block text-sm font-medium text-slate-300 mb-1">{$t('auth.2fa_label')}</label>
          <input
            id="totp"
            type="text"
            bind:value={totpCode}
            required
            maxlength="6"
            pattern="[0-9]{6}"
            autocomplete="one-time-code"
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 text-center text-2xl tracking-[0.5em]"
            placeholder="000000"
          />
        </div>

        <button
          type="submit"
          disabled={loading || totpCode.length !== 6}
          class="w-full bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white py-2 rounded-lg font-medium transition cursor-pointer"
        >
          {loading ? $t('auth.verifying') : $t('auth.verify_btn')}
        </button>

        <button
          type="button"
          onclick={() => { requires2FA = false; pendingToken = ''; totpCode = ''; error = ''; }}
          class="w-full text-slate-400 hover:text-slate-300 py-2 text-sm mt-3 transition cursor-pointer"
        >
          {$t('auth.back_to_login')}
        </button>
      </form>
    {:else}
      <form onsubmit={handleLogin}>
        
        {#if error}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{error}</p>
          </div>
        {/if}

        <div class="mb-4">
          <label for="email" class="block text-sm font-medium text-slate-300 mb-1">{$t('auth.email')}</label>
          <input
            id="email"
            type="email"
            bind:value={email}
            required
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            placeholder="org@example.com"
          />
        </div>

        <div class="mb-6">
          <label for="password" class="block text-sm font-medium text-slate-300 mb-1">{$t('auth.password')}</label>
          <input
            id="password"
            type="password"
            bind:value={password}
            required
            minlength="8"
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            placeholder="••••••••"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          class="w-full bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white py-2 rounded-lg font-medium transition cursor-pointer"
        >
          {loading ? $t('auth.logging_in') : $t('auth.login_btn')}
        </button>
      </form>

      <p class="text-center text-slate-400 text-sm mt-6">
        {$t('auth.no_account')}
        <a href="/signup" class="text-emerald-500 hover:underline ml-1">{$t('auth.signup_link')}</a>
      </p>
    {/if}
  </div>
</div>