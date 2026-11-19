<script>
  import { onMount } from 'svelte';
  import { API_URL } from '$lib/api';
  import { logout } from '$lib/auth';

  let sessions = $state([]);
  let loading = $state(true);
  let error = $state('');
  let successMsg = $state('');
  let token = $state('');
  let revokingId = $state(null);
  let revokingAll = $state(false);

  $effect(() => {
    token = localStorage.getItem('burnerbox_token') || '';
    if (!token) {
      logout('', '/login');
      return;
    }
    loadSessions();
  });

  async function loadSessions() {
    loading = true;
    error = '';
    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/sessions`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (res.status === 401) {
        await handleLogout();
        return;
      }

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        error = errData.error || 'Failed to load active sessions';
        return;
      }

      const data = await res.json();
      sessions = data.sessions || [];
    } catch (err) {
      error = 'Could not connect to backend server';
    } finally {
      loading = false;
    }
  }

  async function revokeSession(id, isCurrent) {
    if (isCurrent && !confirm('Revoking your current session will immediately log you out. Continue?')) {
      return;
    }

    revokingId = id;
    error = '';
    successMsg = '';

    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/sessions/${id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (isCurrent || res.status === 401) {
        await handleLogout();
        return;
      }

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        error = errData.error || 'Failed to revoke session';
        return;
      }

      successMsg = 'Session revoked immediately.';
      await loadSessions();
    } catch (err) {
      error = 'Network error while revoking session';
    } finally {
      revokingId = null;
    }
  }

  async function revokeAllOtherSessions() {
    if (!confirm('Are you sure you want to terminate all other active sessions? All other devices will be disconnected immediately.')) {
      return;
    }

    revokingAll = true;
    error = '';
    successMsg = '';

    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/sessions`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (res.status === 401) {
        await handleLogout();
        return;
      }

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        error = errData.error || 'Failed to revoke other sessions';
        return;
      }

      const data = await res.json();
      successMsg = `Revoked ${data.revoked_count || 0} other active session(s).`;
      await loadSessions();
    } catch (err) {
      error = 'Network error while revoking sessions';
    } finally {
      revokingAll = false;
    }
  }

  async function handleLogout() {
    await logout(token);
  }

  function formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    try {
      const d = new Date(dateStr);
      return d.toLocaleString(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
      });
    } catch {
      return dateStr;
    }
  }
</script>

<svelte:head>
  <title>Active Sessions & Revocation | BurnerBox</title>
</svelte:head>

<div class="min-h-screen bg-slate-900 p-4 md:p-8 text-slate-200">
  <div class="max-w-4xl mx-auto space-y-6">
    
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
      <div>
        <div class="flex items-center gap-2 mb-1">
          <a href="/dashboard" class="text-slate-400 hover:text-white text-sm transition">← Dashboard</a>
          <span class="text-slate-600">/</span>
          <span class="text-slate-300 text-sm font-medium">Sessions</span>
        </div>
        <h1 class="text-2xl font-bold text-white flex items-center gap-2">
          <span>🛡️ Active Sessions & Revocation</span>
        </h1>
        <p class="text-sm text-slate-400 mt-1">
          Track and instantly invalidate active login sessions for your organization.
        </p>
      </div>

      <div class="flex items-center gap-3">
        <button
          onclick={revokeAllOtherSessions}
          disabled={revokingAll || sessions.length <= 1}
          class="bg-rose-900/40 hover:bg-rose-800/60 text-rose-300 border border-rose-700/50 px-4 py-2 rounded-lg text-sm font-medium transition disabled:opacity-40 cursor-pointer"
        >
          {revokingAll ? 'Revoking...' : '🚫 Revoke All Other Sessions'}
        </button>
      </div>
    </div>

    <!-- Zero Tracking Guarantee Alert -->
    <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-4 flex items-start gap-3">
      <span class="text-xl">🔒</span>
      <div class="text-xs text-slate-300 leading-relaxed">
        <strong class="text-white block font-medium mb-0.5">Zero-Tracking Privacy Guarantee</strong>
        In strict adherence to BurnerBox's anonymity architecture, <strong>no IP addresses, device fingerprints, or User-Agent headers</strong> are recorded in session logs. Session tokens are hashed via SHA-256 and verified against the database on every protected request to provide instant revocation without compromising metadata privacy.
      </div>
    </div>

    <!-- Status Messages -->
    {#if error}
      <div class="bg-rose-950/50 border border-rose-800 text-rose-300 px-4 py-3 rounded-lg text-sm flex items-center justify-between">
        <span>⚠️ {error}</span>
        <button onclick={() => error = ''} class="text-rose-400 hover:text-white text-lg">✕</button>
      </div>
    {/if}

    {#if successMsg}
      <div class="bg-emerald-950/50 border border-emerald-800 text-emerald-300 px-4 py-3 rounded-lg text-sm flex items-center justify-between">
        <span>✅ {successMsg}</span>
        <button onclick={() => successMsg = ''} class="text-emerald-400 hover:text-white text-lg">✕</button>
      </div>
    {/if}

    <!-- Sessions List Card -->
    <div class="bg-slate-800 rounded-xl shadow-xl border border-slate-700 overflow-hidden">
      <div class="p-4 border-b border-slate-700/60 flex items-center justify-between">
        <h2 class="font-semibold text-white text-sm uppercase tracking-wider">
          Active Sessions ({sessions.length})
        </h2>
        <button
          onclick={loadSessions}
          disabled={loading}
          class="text-xs text-slate-400 hover:text-slate-200 transition"
        >
          🔄 Refresh
        </button>
      </div>

      {#if loading}
        <div class="p-12 text-center text-slate-400">
          <div class="inline-block animate-spin text-2xl mb-2">🌀</div>
          <p class="text-sm">Validating active sessions...</p>
        </div>
      {:else if sessions.length === 0}
        <div class="p-12 text-center text-slate-500">
          <p class="text-base font-medium">No active sessions found.</p>
        </div>
      {:else}
        <div class="divide-y divide-slate-700/60">
          {#each sessions as s (s.id)}
            <div class="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition hover:bg-slate-750">
              <div class="space-y-1.5">
                <div class="flex items-center gap-2.5">
                  {#if s.is_current}
                    <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                      Current Session
                    </span>
                  {:else}
                    <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-slate-700 text-slate-300">
                      Active Device / Tab
                    </span>
                  {/if}
                  <code class="text-xs font-mono text-slate-400">
                    ID: {s.id.substring(0, 8)}...{s.id.substring(s.id.length - 4)}
                  </code>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-xs text-slate-400">
                  <div>
                    <span class="text-slate-500">Created:</span> {formatDate(s.created_at)}
                  </div>
                  <div>
                    <span class="text-slate-500">Last Active:</span> {formatDate(s.last_seen_at)}
                  </div>
                  <div>
                    <span class="text-slate-500">Expires:</span> {formatDate(s.expires_at)}
                  </div>
                </div>
              </div>

              <div>
                <button
                  onclick={() => revokeSession(s.id, s.is_current)}
                  disabled={revokingId === s.id}
                  class={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer ${
                    s.is_current
                      ? 'bg-slate-700 hover:bg-slate-600 text-slate-200 border border-slate-600'
                      : 'bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800/80'
                  } disabled:opacity-50`}
                >
                  {revokingId === s.id
                    ? 'Revoking...'
                    : s.is_current
                    ? 'Log Out (Revoke)'
                    : 'Revoke Session'}
                </button>
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </div>

  </div>
</div>
