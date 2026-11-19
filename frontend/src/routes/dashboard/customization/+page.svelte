<script>
  import { onMount } from 'svelte';
  import { API_URL } from '$lib/api';
  import { logout } from '$lib/auth';

  let welcomeMessage = $state('');
  let logoURL = $state('');
  let customFields = $state([]);
  let loading = $state(true);
  let saving = $state(false);
  let error = $state('');
  let successMsg = $state('');
  let token = $state('');
  let logoPreviewError = $state(false);

  $effect(() => {
    token = localStorage.getItem('burnerbox_token') || '';
    if (!token) {
      logout('', '/login');
      return;
    }
    loadCustomizationSettings();
  });

  async function loadCustomizationSettings() {
    loading = true;
    error = '';
    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/customization`, {
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
        error = errData.error || 'Failed to load customization settings';
        return;
      }

      const data = await res.json();
      welcomeMessage = data.welcome_message || '';
      logoURL = data.logo_url || '';
      customFields = (data.custom_fields || []).map(f => ({
        ...f,
        optionsText: Array.isArray(f.options) ? f.options.join(', ') : '',
      }));
    } catch (err) {
      error = 'Could not connect to backend server';
    } finally {
      loading = false;
    }
  }

  function addCustomField() {
    customFields.push({
      id: crypto.randomUUID ? crypto.randomUUID() : 'field-' + Date.now(),
      label: '',
      field_type: 'text',
      optionsText: '',
      required: false,
    });
  }

  function removeCustomField(index) {
    customFields.splice(index, 1);
  }

  async function saveCustomization() {
    saving = true;
    error = '';
    successMsg = '';

    // Validate fields before submitting
    for (let i = 0; i < customFields.length; i++) {
      const f = customFields[i];
      if (!f.label || !f.label.trim()) {
        error = `Custom field #${i + 1} requires a label.`;
        saving = false;
        return;
      }
      if (f.field_type === 'select') {
        const opts = (f.optionsText || '').split(',').map(s => s.trim()).filter(Boolean);
        if (opts.length === 0) {
          error = `Select field "${f.label}" must have at least one comma-separated option.`;
          saving = false;
          return;
        }
      }
    }

    const payloadFields = customFields.map(f => ({
      id: f.id,
      label: f.label.trim(),
      field_type: f.field_type,
      options: f.field_type === 'select' ? (f.optionsText || '').split(',').map(s => s.trim()).filter(Boolean) : undefined,
      required: Boolean(f.required),
    }));

    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/customization`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          welcome_message: welcomeMessage,
          logo_url: logoURL.trim(),
          custom_fields: payloadFields,
        }),
      });

      if (res.status === 401) {
        handleLogout();
        return;
      }

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        error = errData.error || 'Failed to save customization settings';
        return;
      }

      successMsg = 'Public submission portal updated successfully!';
    } catch (err) {
      error = 'Network error while saving settings';
    } finally {
      saving = false;
    }
  }

  async function handleLogout() {
    await logout(token);
  }
</script>

<svelte:head>
  <title>Portal Customization | BurnerBox</title>
</svelte:head>

<div class="min-h-screen bg-slate-900 p-4 md:p-8 text-slate-200">
  <div class="max-w-4xl mx-auto space-y-6">
    
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
      <div>
        <div class="flex items-center gap-2 mb-1">
          <a href="/dashboard" class="text-slate-400 hover:text-white text-sm transition">← Dashboard</a>
          <span class="text-slate-600">/</span>
          <span class="text-slate-300 text-sm font-medium">Customization</span>
        </div>
        <h1 class="text-2xl font-bold text-white flex items-center gap-2">
          <span>🎨 Public Submission Portal Customization</span>
        </h1>
        <p class="text-sm text-slate-400 mt-1">
          Customize the appearance, welcome message, and dynamic encrypted fields on your public submission page.
        </p>
      </div>

      <div>
        <button
          onclick={saveCustomization}
          disabled={saving || loading}
          class="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-5 py-2.5 rounded-lg text-sm font-semibold transition cursor-pointer shadow-lg shadow-emerald-950/40"
        >
          {saving ? 'Saving...' : '💾 Save Settings'}
        </button>
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

    {#if loading}
      <div class="bg-slate-800 rounded-xl p-12 text-center text-slate-400 border border-slate-700">
        <div class="inline-block animate-spin text-2xl mb-2">🌀</div>
        <p class="text-sm">Loading portal configuration...</p>
      </div>
    {:else}
      <!-- 1. General Portal Branding & Message -->
      <div class="bg-slate-800 rounded-xl p-6 shadow-xl border border-slate-700 space-y-5">
        <h2 class="text-base font-semibold text-white flex items-center gap-2 border-b border-slate-700/60 pb-3">
          <span>🏢 Branding & Welcome Content</span>
        </h2>

        <!-- Welcome Message -->
        <div class="space-y-1.5">
          <label for="welcomeMsg" class="block text-sm font-medium text-slate-300">
            Welcome Message / Submitter Instructions
          </label>
          <textarea
            id="welcomeMsg"
            bind:value={welcomeMessage}
            rows="3"
            maxlength="1000"
            placeholder="e.g. Welcome to our investigative tips inbox. Please provide as much specific detail as possible..."
            class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
          ></textarea>
          <div class="text-right text-xs text-slate-500">
            {welcomeMessage.length}/1000 characters
          </div>
        </div>

        <!-- Logo URL -->
        <div class="space-y-1.5">
          <label for="logoUrl" class="block text-sm font-medium text-slate-300">
            Organization Logo URL <span class="text-xs text-slate-500 font-normal">(Optional HTTPS Image URL)</span>
          </label>
          <input
            id="logoUrl"
            type="url"
            bind:value={logoURL}
            placeholder="https://your-outlet.com/assets/logo.png"
            class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
          />
          <p class="text-xs text-slate-400">
            Provide a direct public HTTPS URL to your organization's logo. It will be displayed at the top of your submission portal.
          </p>

          {#if logoURL.trim()}
            <div class="mt-3 p-3 bg-slate-900/80 rounded-lg border border-slate-700/60 flex items-center gap-4">
              <span class="text-xs text-slate-400">Preview:</span>
              <img
                src={logoURL.trim()}
                alt="Logo preview"
                class="h-10 max-w-[200px] object-contain rounded bg-white/5 p-1 border border-slate-700"
                onerror={() => logoPreviewError = true}
                onload={() => logoPreviewError = false}
              />
              {#if logoPreviewError}
                <span class="text-xs text-amber-400">⚠️ Unable to load image from URL</span>
              {/if}
            </div>
          {/if}
        </div>
      </div>

      <!-- 2. Dynamic Custom Fields Builder -->
      <div class="bg-slate-800 rounded-xl p-6 shadow-xl border border-slate-700 space-y-5">
        <div class="flex items-center justify-between border-b border-slate-700/60 pb-3">
          <div>
            <h2 class="text-base font-semibold text-white flex items-center gap-2">
              <span>📋 Custom Form Fields</span>
            </h2>
            <p class="text-xs text-slate-400 mt-0.5">
              Add structured questions to your public portal. All responses are bundled directly into the encrypted payload.
            </p>
          </div>

          <button
            onclick={addCustomField}
            class="bg-slate-700 hover:bg-slate-600 text-white px-3.5 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer flex items-center gap-1.5"
          >
            <span>➕</span> Add Field
          </button>
        </div>

        <!-- CRITICAL ANONYMITY WARNING BOX (MANDATORY per security specification) -->
        <div class="bg-amber-950/40 border border-amber-800/80 rounded-xl p-4 flex items-start gap-3">
          <span class="text-2xl">⚠️</span>
          <div class="text-xs text-amber-200/90 leading-relaxed">
            <strong class="text-amber-100 font-semibold block mb-1">
              Whistleblower Anonymity Warning
            </strong>
            Avoid fields that could identify the submitter (e.g. employee ID, department, name, direct phone) unless absolutely necessary for your process. Every identifying question increases the risk of de-anonymizing sources.
          </div>
        </div>

        <!-- Custom Fields List -->
        {#if customFields.length === 0}
          <div class="p-8 text-center bg-slate-900/40 rounded-xl border border-dashed border-slate-700">
            <p class="text-sm text-slate-400">No custom fields configured.</p>
            <p class="text-xs text-slate-500 mt-1">Submitters will only see the main encrypted message box and file upload.</p>
            <button
              onclick={addCustomField}
              class="mt-3 text-emerald-400 hover:text-emerald-300 text-xs font-semibold"
            >
              + Add your first custom field
            </button>
          </div>
        {:else}
          <div class="space-y-4">
            {#each customFields as field, index (field.id || index)}
              <div class="bg-slate-900/90 border border-slate-700 rounded-xl p-4 space-y-3 relative group">
                <div class="flex items-center justify-between">
                  <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Field #{index + 1}
                  </span>
                  <button
                    onclick={() => removeCustomField(index)}
                    class="text-rose-400 hover:text-rose-300 text-xs font-medium px-2 py-1 rounded bg-rose-950/30 hover:bg-rose-950/60 border border-rose-900/50 transition cursor-pointer"
                  >
                    🗑️ Remove
                  </button>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div class="sm:col-span-2 space-y-1">
                    <label for={`field-label-${index}`} class="block text-xs font-medium text-slate-300">Question / Label</label>
                    <input
                      id={`field-label-${index}`}
                      type="text"
                      bind:value={field.label}
                      placeholder="e.g. What geographical region does this concern?"
                      class="w-full bg-slate-800 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                    />
                  </div>

                  <div class="space-y-1">
                    <label for={`field-type-${index}`} class="block text-xs font-medium text-slate-300">Input Type</label>
                    <select
                      id={`field-type-${index}`}
                      bind:value={field.field_type}
                      class="w-full bg-slate-800 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                    >
                      <option value="text">Single-line Text</option>
                      <option value="textarea">Multi-line Textarea</option>
                      <option value="select">Dropdown Select</option>
                    </select>
                  </div>
                </div>

                {#if field.field_type === 'select'}
                  <div class="space-y-1 pt-1">
                    <label for={`field-opts-${index}`} class="block text-xs font-medium text-slate-300">
                      Dropdown Options <span class="text-slate-500 font-normal">(Comma-separated)</span>
                    </label>
                    <input
                      id={`field-opts-${index}`}
                      type="text"
                      bind:value={field.optionsText}
                      placeholder="Low, Medium, High, Critical"
                      class="w-full bg-slate-800 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                {/if}

                <div class="flex items-center gap-2 pt-1">
                  <input
                    type="checkbox"
                    id={`req-${index}`}
                    bind:checked={field.required}
                    class="rounded bg-slate-800 border-slate-700 text-emerald-500 focus:ring-emerald-500 h-3.5 w-3.5"
                  />
                  <label for={`req-${index}`} class="text-xs text-slate-300 select-none cursor-pointer">
                    Required field (submitter must answer before encrypting)
                  </label>
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}

  </div>
</div>
