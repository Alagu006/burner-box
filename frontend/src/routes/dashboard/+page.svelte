<script>
  import { onMount } from 'svelte';
  import { API_URL } from '$lib/api';
  import { clearDerivedKey } from '$lib/crypto';

  let orgData = $state(null);
  let error = $state('');
  let loading = $state(true);
  let token = $state('');
  let hostOrigin = $state('');

  // Derived state to safely calculate the URL format on the client side
  let submissionUrl = $derived(
    hostOrigin && orgData?.submission_slug 
      ? `${hostOrigin}/submit/${orgData.submission_slug}` 
      : ''
  );

  $effect(() => {
    // Read local configuration safely inside client-side effect context
    token = localStorage.getItem('burnerbox_token') || '';
    hostOrigin = window.location.origin;
    
    const stored = localStorage.getItem('burnerbox_org');
    if (stored) {
      try {
        orgData = JSON.parse(stored);
      } catch (e) {
        // Invalid JSON, silently fallback
      }
    }

    if (token) {
      loadDashboardData();
    } else {
      error = 'Not logged in';
      loading = false;
      setTimeout(() => window.location.href = '/login', 2000);
    }
  });

  async function loadDashboardData() {
    try {
      const response = await fetch(`${API_URL}/api/v1/dashboard/`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.status === 401) {
        handleLogout();
        return;
      }

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        error = errData.error || `Error: ${response.status}`;
        loading = false;
        return;
      }

      const data = await response.json();
      
      orgData = {
        ...orgData,
        dashboardMessage: data.message,
        dashboardEmail: data.email,
      };

    } catch (err) {
      error = 'Cannot connect to backend. Is it running?';
    } finally {
      loading = false;
    }
  }

  function handleLogout() {
    clearDerivedKey();
    localStorage.removeItem('burnerbox_token');
    localStorage.removeItem('burnerbox_org');
    window.location.href = '/login';
  }

  function copySubmissionUrl() {
    if (!submissionUrl) return;
    navigator.clipboard.writeText(submissionUrl);
    alert('URL copied!');
  }
</script>

<div class="min-h-screen bg-slate-900 p-4">
  <div class="max-w-4xl mx-auto">
    
    <!-- Header -->
    <div class="flex justify-between items-center mb-8">
      <h1 class="text-2xl font-bold text-white">🔥 BurnerBox Dashboard</h1>
      <button
        onclick={handleLogout}
        class="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer"
      >
        🚪 Logout
      </button>
    </div>

    {#if loading}
      <div class="bg-slate-800 rounded-lg p-12 shadow-xl text-center">
        <div class="text-4xl mb-4">⏳</div>
        <p class="text-slate-400 text-lg">Loading your dashboard...</p>
        <p class="text-slate-500 text-xs mt-2">Token: {token ? 'Found' : 'Missing'}</p>
      </div>
      
    {:else if error}
      <div class="bg-red-900/50 border border-red-500 rounded-lg p-6 shadow-xl">
        <p class="text-red-400 text-lg mb-2">❌ {error}</p>
        <button
          onclick={() => window.location.href = '/login'}
          class="mt-4 bg-red-700 hover:bg-red-600 text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer"
        >
          Go to Login
        </button>
      </div>
      
    {:else if orgData}
      <!-- Welcome Card -->
      <div class="bg-slate-800 rounded-lg p-6 mb-6 shadow-xl">
        <h2 class="text-xl font-semibold text-white mb-2">
          Welcome, {orgData.name || 'Organization'}!
        </h2>
        <p class="text-slate-400 text-sm">
          {orgData.dashboardMessage || 'Manage your anonymous submission portal and team.'}
        </p>
        
        <!-- Quick Links -->
        <div class="flex gap-4 mt-4">
          <a href="/dashboard/security" class="text-emerald-400 hover:text-emerald-300 text-sm">
            🔐 Security Settings
          </a>
          <a href="/dashboard/team" class="text-emerald-400 hover:text-emerald-300 text-sm">
            👥 Team Members
          </a>
        </div>
      </div>

      <!-- Submission URL Card -->
      <div class="bg-slate-800 rounded-lg p-6 mb-6 shadow-xl">
        <h3 class="text-lg font-semibold text-white mb-3">📨 Your Anonymous Submission Portal</h3>
        <p class="text-slate-400 text-sm mb-3">
          Share this secret URL with sources. They can submit tips anonymously.
        </p>
        <div class="bg-slate-900 rounded-lg p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <code class="text-emerald-400 text-sm break-all">
            {submissionUrl || 'Generating URL...'}
          </code>
          <button
            onclick={copySubmissionUrl}
            disabled={!submissionUrl}
            class="bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer whitespace-nowrap"
          >
            📋 Copy URL
          </button>
        </div>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="bg-slate-800 rounded-lg p-5 shadow-xl">
          <p class="text-slate-400 text-sm mb-1">New Submissions</p>
          <p class="text-3xl font-bold text-emerald-500">0</p>
          <p class="text-slate-500 text-xs mt-1">Unread tips</p>
        </div>
        <div class="bg-slate-800 rounded-lg p-5 shadow-xl">
          <p class="text-slate-400 text-sm mb-1">Total Submissions</p>
          <p class="text-3xl font-bold text-white">0</p>
          <p class="text-slate-500 text-xs mt-1">All time</p>
        </div>
        <div class="bg-slate-800 rounded-lg p-5 shadow-xl">
          <p class="text-slate-400 text-sm mb-1">Team Members</p>
          <p class="text-3xl font-bold text-white">1</p>
          <p class="text-slate-500 text-xs mt-1">Including you</p>
        </div>
      </div>

      <!-- Recent Activity -->
      <div class="bg-slate-800 rounded-lg p-6 mt-6 shadow-xl">
        <h3 class="text-lg font-semibold text-white mb-4">📋 Recent Activity</h3>
        <div class="text-center py-8">
          <p class="text-slate-500">No submissions yet</p>
          <p class="text-slate-600 text-sm mt-1">
            Share your submission URL to start receiving anonymous tips
          </p>
        </div>
      </div>

      <!-- Submissions Quick View (Cleanly structured inside the core app block) -->
      <div class="bg-slate-800 rounded-lg p-6 mt-6 shadow-xl">
        <div class="flex justify-between items-center mb-4">
          <h3 class="text-lg font-semibold text-white">📨 Recent Submissions</h3>
          <a href="/dashboard/submissions" class="text-emerald-400 hover:text-emerald-300 text-sm">
            View All →
          </a>
        </div>
        <div class="text-center py-8">
          <p class="text-slate-500">No submissions yet</p>
          <p class="text-slate-600 text-sm mt-1">
            Share your submission URL: <span class="text-emerald-400">{orgData.submission_slug ? `/submit/${orgData.submission_slug}` : '...'}</span>
          </p>
        </div>
      </div>

    {:else}
      <div class="bg-slate-800 rounded-lg p-8 text-center shadow-xl">
        <p class="text-slate-400">No organization data found.</p>
        <button
          onclick={() => window.location.href = '/login'}
          class="mt-4 bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer"
        >
          Go to Login
        </button>
      </div>
    {/if}
  </div>
</div>
