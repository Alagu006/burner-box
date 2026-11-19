<script>
  import { API_URL } from '$lib/api';
  import { logout } from '$lib/auth';

  let token = $state('');
  let members = $state([]);
  let newEmail = $state('');
  let newRole = $state('reader');
  let message = $state('');
  let error = $state('');
  let loading = $state(true);

  $effect(() => {
    token = localStorage.getItem('burnerbox_token') || '';
    if (!token) {
      logout('', '/login');
      return;
    }
    loadMembers();
  });

  async function apiCall(method, path, body = null) {
    const options = {
      method,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    };
    if (body) options.body = JSON.stringify(body);
    const response = await fetch(`${API_URL}/api/v1/dashboard/team${path}`, options);
    if (response.status === 401) {
      await logout(token);
      return {};
    }
    return response.json();
  }

  async function loadMembers() {
    try {
      const data = await apiCall('GET', '/');
      members = data.members || [];
    } catch (e) {
      error = 'Failed to load team members';
    }
    loading = false;
  }

  async function inviteMember(e) {
    e.preventDefault();
    error = '';
    message = '';
    try {
      const data = await apiCall('POST', '/invite', { email: newEmail, role: newRole });
      if (data.error) {
        error = data.error;
      } else {
        message = `✅ Invited ${newEmail} as ${newRole}`;
        newEmail = '';
        loadMembers();
      }
    } catch (e) {
      error = 'Failed to invite member';
    }
  }

  async function removeMember(id, email) {
    if (!confirm(`Remove ${email}?`)) return;
    try {
      await apiCall('DELETE', `/${id}`);
      loadMembers();
    } catch (e) {
      error = 'Failed to remove member';
    }
  }

  function roleBadge(role) {
    const colors = {
      admin: 'bg-purple-600',
      responder: 'bg-blue-600',
      reader: 'bg-slate-600',
    };
    return colors[role] || 'bg-slate-600';
  }
</script>

<div class="min-h-screen bg-slate-900 p-4">
  <div class="max-w-2xl mx-auto">
    
    <a href="/dashboard" class="text-slate-400 hover:text-white text-sm mb-4 inline-block">
      ← Back to Dashboard
    </a>

    <h1 class="text-2xl font-bold text-white mb-6">👥 Team Members</h1>

    {#if message}
      <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-3 mb-4">
        <p class="text-emerald-400 text-sm">{message}</p>
      </div>
    {/if}

    {#if error}
      <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
        <p class="text-red-400 text-sm">{error}</p>
      </div>
    {/if}

    <!-- Invite Form -->
    <div class="bg-slate-800 rounded-lg p-6 shadow-xl mb-6">
      <h2 class="text-lg font-semibold text-white mb-4">Invite New Member</h2>
      
      <form onsubmit={inviteMember}>
        <div class="mb-4">
          <input
            type="email"
            bind:value={newEmail}
            required
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-emerald-500"
            placeholder="colleague@example.com"
          />
        </div>

        <div class="mb-4">
          <select
            bind:value={newRole}
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-emerald-500"
          >
            <option value="reader">Reader - Can view submissions</option>
            <option value="responder">Responder - Can view & reply</option>
            <option value="admin">Admin - Full access</option>
          </select>
        </div>

        <button
          type="submit"
          class="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg text-sm transition"
        >
          📨 Send Invitation
        </button>
      </form>
    </div>

    <!-- Members List -->
    <div class="bg-slate-800 rounded-lg p-6 shadow-xl">
      <h2 class="text-lg font-semibold text-white mb-4">
        Current Members ({members.length})
      </h2>

      {#if loading}
        <p class="text-slate-400">Loading...</p>
      {:else if members.length === 0}
        <p class="text-slate-400">No team members invited yet.</p>
      {:else}
        <div class="space-y-3">
          {#each members as member}
            <div class="flex items-center justify-between bg-slate-700 rounded-lg p-3">
              <div>
                <p class="text-white text-sm">{member.email}</p>
                <span class="text-xs text-white px-2 py-0.5 rounded {roleBadge(member.role)}">
                  {member.role}
                </span>
              </div>
              <button
                onclick={() => removeMember(member.id, member.email)}
                class="text-red-400 hover:text-red-300 text-sm transition"
              >
                Remove
              </button>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  </div>
</div>