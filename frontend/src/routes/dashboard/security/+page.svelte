<script>
  import { API_URL } from '$lib/api';
  import { generateKeyPair, encryptForRecipient, getStoredPrivateKey, getCachedDerivedKey } from '$lib/crypto';

  let token = $state('');
  let qrCode = $state('');
  let secret = $state('');
  let code = $state('');
  let message = $state('');
  let error = $state('');
  let totpEnabled = $state(false);
  let loading = $state(true);
  let setupMode = $state(false);

  // Key rotation state
  let rotating = $state(false);
  let rotationProgress = $state('');
  let rotationError = $state('');

  // Dead man's switch state
  let dmsEnabled = $state(false);
  let dmsTriggerDays = $state(30);
  let dmsActionType = $state('email');
  let dmsLoading = $state(true);
  let dmsSaving = $state(false);
  let dmsMessage = $state('');
  let dmsError = $state('');
  let dmsPassword = $state('');
  let dmsTotpCode = $state('');

  // Submission deadline state
  let deadlineDate = $state('');
  let deadlineLoading = $state(true);
  let deadlineSaving = $state(false);
  let deadlineMessage = $state('');
  let deadlineError = $state('');

  // Configurable retention state
  let retentionDays = $state('');
  let retentionLoading = $state(true);
  let retentionSaving = $state(false);
  let retentionMessage = $state('');
  let retentionError = $state('');

  // Notification settings state (webhook + email)
  let webhookURL = $state('');
  let notificationEmail = $state('');
  let notifLoading = $state(true);
  let notifSaving = $state(false);
  let notifMessage = $state('');
  let notifError = $state('');

  $effect(() => {
    token = localStorage.getItem('burnerbox_token') || '';
    check2FAStatus();
    loadDeadMansSwitch();
    loadDeadline();
    loadRetention();
    loadNotifications();
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
    
    const response = await fetch(`${API_URL}/api/v1/dashboard/2fa${path}`, options);
    return response.json();
  }

  async function check2FAStatus() {
    try {
      const data = await apiCall('GET', '/status');
      totpEnabled = data.totp_enabled;
    } catch (e) {
      error = 'Failed to check 2FA status';
    }
    loading = false;
  }

  async function setup2FA() {
    error = '';
    message = '';
    try {
      const data = await apiCall('POST', '/setup');
      qrCode = data.qr_code;
      secret = data.manual_key;
      setupMode = true;
    } catch (e) {
      error = 'Failed to setup 2FA';
    }
  }

  async function verify2FA() {
    error = '';
    message = '';
    try {
      const data = await apiCall('POST', '/verify', { code });
      if (data.error) {
        error = data.error;
      } else {
        message = '✅ 2FA enabled successfully!';
        totpEnabled = true;
        setupMode = false;
        code = '';
      }
    } catch (e) {
      error = 'Failed to verify code';
    }
  }

  async function disable2FA() {
    if (!confirm('Are you sure you want to disable 2FA? This makes your account less secure.')) return;
    error = '';
    message = '';
    try {
      const data = await apiCall('POST', '/disable', { code });
      if (data.error) {
        error = data.error;
      } else {
        message = '2FA disabled';
        totpEnabled = false;
        code = '';
      }
    } catch (e) {
      error = 'Failed to disable 2FA';
    }
  }

  async function rotateKeys() {
    const confirmed = confirm(
      'KEY ROTATION WARNING:\n\n' +
      'This will generate a new encryption keypair and re-encrypt all existing ' +
      'submissions. The old key will no longer work.\n\n' +
      'You MUST be logged in with your password to complete this process. ' +
      'Any team members who have cached the old private key will need to ' +
      're-login.\n\n' +
      'Submissions that cannot be decrypted (e.g. from a lost key) will be ' +
      'skipped with a warning.\n\n' +
      'Continue?'
    );
    if (!confirmed) return;

    rotating = true;
    rotationError = '';
    rotationProgress = 'Generating new keypair...';

    try {
      const oldPrivateKey = await getStoredPrivateKey();
      if (!oldPrivateKey) {
        rotationError = 'Cannot read current private key. Are you logged in with your password?';
        rotating = false;
        return;
      }

      const newKeyPair = await generateKeyPair();
      rotationProgress = 'Updating public key on server...';

      const res = await fetch(`${API_URL}/api/v1/dashboard/public-key`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ public_key: newKeyPair.publicKey }),
      });

      if (!res.ok) {
        const data = await res.json();
        rotationError = data.error || 'Failed to update public key on server';
        rotating = false;
        return;
      }

      rotationProgress = 'Fetching submissions for re-encryption...';

      const listRes = await fetch(`${API_URL}/api/v1/dashboard/submissions/`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!listRes.ok) {
        rotationError = 'Failed to fetch submissions list';
        rotating = false;
        return;
      }

      const listData = await listRes.json();
      const subs = listData.submissions || [];
      let reencrypted = 0;
      let skipped = 0;

      for (let i = 0; i < subs.length; i++) {
        const sub = subs[i];
        rotationProgress = `Re-encrypting submission ${i + 1}/${subs.length}...`;

        if (!sub.encrypted_message || !sub.encryption_meta) {
          skipped++;
          continue;
        }

        try {
          const meta = JSON.parse(sub.encryption_meta);
          const decrypted = await encryptForRecipient(
            '',
            newKeyPair.publicKey
          );
          // Actually decrypt first, then re-encrypt
          const { decryptFromSender } = await import('$lib/crypto');
          const plaintext = await decryptFromSender(
            {
              ciphertext: sub.encrypted_message,
              nonce: meta.nonce,
              encryptedKey: meta.encryptedKey,
              boxNonce: meta.boxNonce,
              senderPublicKey: meta.senderPublicKey,
            },
            oldPrivateKey
          );

          const reEnc = await encryptForRecipient(plaintext, newKeyPair.publicKey);
          const newMeta = {
            nonce: reEnc.nonce,
            encryptedKey: reEnc.encryptedKey,
            boxNonce: reEnc.boxNonce,
            senderPublicKey: reEnc.senderPublicKey,
          };

          await fetch(`${API_URL}/api/v1/dashboard/submissions/${sub.id}`, {
            method: 'PUT',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              encrypted_message: reEnc.ciphertext,
              encryption_meta: JSON.stringify(newMeta),
            }),
          });

          reencrypted++;
        } catch {
          skipped++;
        }
      }

      // Store new private key encrypted in localStorage using the cached derived key.
      // We preserve the ORIGINAL salt from the stored key so that login can still
      // re-derive the same key from the user's password.
      try {
        const derivedKey = getCachedDerivedKey();
        const storedRaw = localStorage.getItem('burnerbox_private_key');
        let originalSalt = '';
        try {
          const parsed = JSON.parse(storedRaw);
          originalSalt = parsed.salt || '';
        } catch { /* raw format, no salt */ }

        if (derivedKey && originalSalt) {
          const s = await import('libsodium-wrappers');
          await s.default.ready;
          const nonce = s.default.randombytes_buf(s.default.crypto_secretbox_NONCEBYTES);
          const plaintext = s.default.from_base64(newKeyPair.privateKey, s.default.base64_variants.ORIGINAL);
          const ciphertext = s.default.crypto_secretbox_easy(plaintext, nonce, derivedKey);
          localStorage.setItem('burnerbox_private_key', JSON.stringify({
            encrypted: s.default.to_base64(ciphertext, s.default.base64_variants.ORIGINAL),
            salt: originalSalt,
            nonce: s.default.to_base64(nonce, s.default.base64_variants.ORIGINAL),
          }));
        } else {
          localStorage.setItem('burnerbox_private_key', newKeyPair.privateKey);
        }
      } catch {
        localStorage.setItem('burnerbox_private_key', newKeyPair.privateKey);
      }

      rotationProgress = '';
      message = `Key rotation complete. ${reencrypted} submission(s) re-encrypted, ${skipped} skipped.`;
      rotating = false;

    } catch (e) {
      rotationError = 'Key rotation failed: ' + (e.message || 'Unknown error');
      rotating = false;
      rotationProgress = '';
    }
  }

  async function loadDeadMansSwitch() {
    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/dead-mans-switch`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        dmsEnabled = data.enabled;
        dmsTriggerDays = data.trigger_days || 30;
        dmsActionType = data.action_type || 'email';
      }
    } catch { /* no config yet */ }
    dmsLoading = false;
  }

  async function saveDeadMansSwitch() {
    if (!confirm('This will configure the dead man\'s switch. Are you sure?')) return;
    dmsSaving = true;
    dmsError = '';
    dmsMessage = '';
    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/dead-mans-switch`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          enabled: dmsEnabled,
          trigger_days: dmsTriggerDays,
          action_type: dmsActionType,
          password: dmsPassword || undefined,
          totp_code: dmsTotpCode || undefined,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        dmsMessage = 'Dead man\'s switch updated.';
        dmsPassword = '';
        dmsTotpCode = '';
      } else {
        dmsError = data.error || 'Failed to save';
      }
    } catch {
      dmsError = 'Network error';
    }
    dmsSaving = false;
  }

  async function loadDeadline() {
    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/submission-settings`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        if (data.deadline) {
          // Convert to datetime-local input format
          deadlineDate = data.deadline.substring(0, 16);
        }
      }
    } catch { /* skip */ }
    deadlineLoading = false;
  }

  async function saveDeadline() {
    deadlineSaving = true;
    deadlineError = '';
    deadlineMessage = '';

    try {
      let body;
      if (deadlineDate) {
        body = { deadline: new Date(deadlineDate).toISOString() };
      } else {
        body = { deadline: null };
      }

      const res = await fetch(`${API_URL}/api/v1/dashboard/submission-settings`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (res.ok) {
        deadlineMessage = deadlineDate ? 'Deadline updated.' : 'Deadline removed — portal always open.';
      } else {
        deadlineError = data.error || 'Failed to save';
      }
    } catch {
      deadlineError = 'Network error';
    }
    deadlineSaving = false;
  }

  // ---- Retention settings ----
  async function loadRetention() {
    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/retention`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        retentionDays = data.retention_days != null ? String(data.retention_days) : '';
      }
    } catch { /* skip */ }
    retentionLoading = false;
  }

  async function saveRetention() {
    retentionSaving = true;
    retentionError = '';
    retentionMessage = '';
    try {
      const body = retentionDays ? { retention_days: parseInt(retentionDays) } : { retention_days: null };
      const res = await fetch(`${API_URL}/api/v1/dashboard/retention`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (res.ok) {
        retentionMessage = retentionDays
          ? `Submissions older than ${retentionDays} days will be auto-deleted.`
          : 'Retention set to indefinite — no auto-deletion.';
      } else {
        retentionError = data.error || 'Failed to save';
      }
    } catch {
      retentionError = 'Network error';
    }
    retentionSaving = false;
  }

  // ---- Notification settings ----
  async function loadNotifications() {
    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/notifications`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        webhookURL = data.webhook_url || '';
        notificationEmail = data.notification_email || '';
      }
    } catch { /* skip */ }
    notifLoading = false;
  }

  async function saveNotifications() {
    notifSaving = true;
    notifError = '';
    notifMessage = '';
    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/notifications`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          webhook_url: webhookURL,
          notification_email: notificationEmail,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        notifMessage = 'Notification settings updated.';
      } else {
        notifError = data.error || 'Failed to save';
      }
    } catch {
      notifError = 'Network error';
    }
    notifSaving = false;
  }
</script>

<div class="min-h-screen bg-slate-900 p-4">
  <div class="max-w-2xl mx-auto">
    
    <!-- Back -->
    <a href="/dashboard" class="text-slate-400 hover:text-white text-sm mb-4 inline-block">
      ← Back to Dashboard
    </a>

    <h1 class="text-2xl font-bold text-white mb-6">🔐 Security Settings</h1>

    {#if loading}
      <div class="bg-slate-800 rounded-lg p-8 text-center">
        <p class="text-slate-400">Loading...</p>
      </div>
    {:else}
      
      <!-- 2FA Status Card -->
      <div class="bg-slate-800 rounded-lg p-6 shadow-xl mb-6">
        <h2 class="text-lg font-semibold text-white mb-4">
          Two-Factor Authentication (2FA)
        </h2>

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

        {#if totpEnabled}
          <div class="flex items-center gap-3 mb-4">
            <span class="text-emerald-500 text-2xl">✅</span>
            <div>
              <p class="text-white font-medium">2FA is Enabled</p>
              <p class="text-slate-400 text-sm">Your account is extra secure</p>
            </div>
          </div>

          <div class="mb-4">
            <label for="disable-code" class="block text-sm text-slate-300 mb-1">
              Enter current 2FA code to disable
            </label>
            <input
              id="disable-code"
              type="text"
              bind:value={code}
              maxlength="6"
              class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-red-500"
              placeholder="000000"
            />
          </div>

          <button
            onclick={disable2FA}
            class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm transition"
          >
            Disable 2FA
          </button>

        {:else if setupMode}
          <p class="text-slate-300 mb-4">
            Scan this QR code with Google Authenticator or any TOTP app:
          </p>

          <div class="bg-white p-4 rounded-lg inline-block mb-4">
            <img src={qrCode} alt="QR Code" class="w-48 h-48" />
          </div>

          <p class="text-slate-400 text-sm mb-2">
            Or enter this code manually:
          </p>
          <code class="bg-slate-900 text-emerald-400 p-2 rounded block mb-4 text-sm break-all">
            {secret}
          </code>

          <div class="mb-4">
            <label for="verify-code" class="block text-sm text-slate-300 mb-1">
              Enter the 6-digit code from your app
            </label>
            <input
              id="verify-code"
              type="text"
              bind:value={code}
              maxlength="6"
              class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-emerald-500"
              placeholder="000000"
            />
          </div>

          <button
            onclick={verify2FA}
            class="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg text-sm transition"
          >
            Verify & Enable 2FA
          </button>

        {:else}
          <div class="flex items-center gap-3 mb-4">
            <span class="text-red-500 text-2xl">⚠️</span>
            <div>
              <p class="text-white font-medium">2FA is Disabled</p>
              <p class="text-slate-400 text-sm">Add an extra layer of security</p>
            </div>
          </div>

          <button
            onclick={setup2FA}
            class="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg text-sm transition"
          >
            Enable 2FA
          </button>
        {/if}
      </div>

      <!-- Key Rotation Card -->
      <div class="bg-slate-800 rounded-lg p-6 shadow-xl">
        <h2 class="text-lg font-semibold text-white mb-4">
          Encryption Key Rotation
        </h2>

        <p class="text-slate-400 text-sm mb-4">
          Generate a new encryption keypair and re-encrypt all existing submissions.
          The old key will no longer be able to decrypt messages.
        </p>

        {#if rotationError}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{rotationError}</p>
          </div>
        {/if}

        {#if rotating}
          <div class="bg-blue-900/50 border border-blue-500 rounded-lg p-3 mb-4">
            <p class="text-blue-400 text-sm">{rotationProgress}</p>
          </div>
        {/if}

        <button
          onclick={rotateKeys}
          disabled={rotating}
          class="bg-yellow-600 hover:bg-yellow-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer"
        >
          {rotating ? 'Rotating...' : 'Rotate Encryption Keys'}
        </button>

        <p class="text-slate-500 text-xs mt-3">
          Team members will need to re-login after key rotation.
        </p>
      </div>

      <!-- Dead Man's Switch Card -->
      <div class="bg-slate-800 rounded-lg p-6 shadow-xl mt-6">
        <h2 class="text-lg font-semibold text-white mb-4">
          Dead Man's Switch
        </h2>

        <p class="text-slate-400 text-sm mb-4">
          If you don't log in within the configured number of days, a preset action
          will be triggered automatically. This is useful for ensuring data reaches
          the public if something happens to you.
        </p>

        {#if dmsMessage}
          <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-3 mb-4">
            <p class="text-emerald-400 text-sm">{dmsMessage}</p>
          </div>
        {/if}
        {#if dmsError}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{dmsError}</p>
          </div>
        {/if}

        {#if dmsLoading}
          <p class="text-slate-400 text-sm">Loading...</p>
        {:else}
          <div class="space-y-4">
            <!-- Enable toggle -->
            <label class="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                bind:checked={dmsEnabled}
                class="w-4 h-4 rounded bg-slate-700 border-slate-600 text-emerald-500"
              />
              <span class="text-slate-300 text-sm">Enable dead man's switch</span>
            </label>

            {#if dmsEnabled}
              <!-- Trigger days -->
              <div>
                <label for="triggerDays" class="block text-sm text-slate-300 mb-1">
                  Trigger after (days without login)
                </label>
                <input
                  id="triggerDays"
                  type="number"
                  bind:value={dmsTriggerDays}
                  min="1"
                  max="365"
                  class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-emerald-500"
                />
              </div>

              <!-- Action type -->
              <div>
                <label for="actionType" class="block text-sm text-slate-300 mb-1">
                  Action to trigger
                </label>
                <select
                  id="actionType"
                  bind:value={dmsActionType}
                  class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-emerald-500"
                >
                  <option value="email">Send email notification</option>
                  <option value="publish">Release submissions publicly</option>
                  <option value="delete">Delete all data</option>
                </select>
              </div>

              <!-- Re-authentication: password -->
              <div>
                <label for="dmsPassword" class="block text-sm text-slate-300 mb-1">
                  Confirm password
                </label>
                <input
                  id="dmsPassword"
                  type="password"
                  bind:value={dmsPassword}
                  placeholder="Your account password"
                  required
                  class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-emerald-500"
                />
              </div>

              <!-- Re-authentication: TOTP (shown only if 2FA enabled) -->
              {#if totpEnabled}
                <div>
                  <label for="dmsTotp" class="block text-sm text-slate-300 mb-1">
                    Two-factor code
                  </label>
                  <input
                    id="dmsTotp"
                    type="text"
                    bind:value={dmsTotpCode}
                    placeholder="6-digit code"
                    maxlength="6"
                    required
                    class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              {/if}

              <div class="bg-yellow-900/50 border border-yellow-500 rounded-lg p-3">
                <p class="text-yellow-400 text-xs">
                  ⚠️ Enabling requires your password{#if totpEnabled} and two-factor code{/if} to confirm.
                  Email actions send a metadata-only notification to your notification email (requires SMTP).
                  Publish action records the trigger in a transparency log.
                  Delete action is not yet implemented.
                </p>
              </div>
            {/if}

            <button
              onclick={saveDeadMansSwitch}
              disabled={dmsSaving}
              class="bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer"
            >
              {dmsSaving ? 'Saving...' : 'Save Settings'}
            </button>
          </div>
        {/if}
      </div>
    {/if}

    <!-- Submission Deadline Card -->
    <div class="bg-slate-800 rounded-lg p-6 shadow-xl mt-6">
      <h2 class="text-lg font-semibold text-white mb-4">
        Submission Deadline
      </h2>

      <p class="text-slate-400 text-sm mb-4">
        Close your submission portal on a specific date. After this date, new submissions
        will be rejected. Leave empty to keep the portal always open.
      </p>

      {#if deadlineMessage}
        <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-3 mb-4">
          <p class="text-emerald-400 text-sm">{deadlineMessage}</p>
        </div>
      {/if}
      {#if deadlineError}
        <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
          <p class="text-red-400 text-sm">{deadlineError}</p>
        </div>
      {/if}

      {#if deadlineLoading}
        <p class="text-slate-400 text-sm">Loading...</p>
      {:else}
        <div class="space-y-4">
          <div>
            <label for="deadline" class="block text-sm text-slate-300 mb-1">
              Deadline (optional)
            </label>
            <input
              id="deadline"
              type="datetime-local"
              bind:value={deadlineDate}
              class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-emerald-500"
            />
            <p class="text-slate-500 text-xs mt-1">
              {deadlineDate ? `Submissions close on ${new Date(deadlineDate).toLocaleString()}` : 'No deadline set — portal always open'}
            </p>
          </div>

          <div class="flex gap-2">
            <button
              onclick={saveDeadline}
              disabled={deadlineSaving}
              class="bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer"
            >
              {deadlineSaving ? 'Saving...' : 'Save Deadline'}
            </button>
            {#if deadlineDate}
              <button
                onclick={() => { deadlineDate = ''; saveDeadline(); }}
                disabled={deadlineSaving}
                class="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer"
              >
                Remove Deadline
              </button>
            {/if}
          </div>
        </div>
      {/if}
    </div>

    <!-- Configurable Retention Card -->
    <div class="bg-slate-800 rounded-lg p-6 shadow-xl mt-6">
      <h2 class="text-lg font-semibold text-white mb-4">
        Data Retention Policy
      </h2>

      <p class="text-slate-400 text-sm mb-4">
        Auto-delete submissions, files, notes, and thread messages after N days.
        We encourage you to set a real policy to minimize data exposure.
      </p>

      {#if retentionMessage}
        <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-3 mb-4">
          <p class="text-emerald-400 text-sm">{retentionMessage}</p>
        </div>
      {/if}
      {#if retentionError}
        <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
          <p class="text-red-400 text-sm">{retentionError}</p>
        </div>
      {/if}

      {#if retentionLoading}
        <p class="text-slate-400 text-sm">Loading...</p>
      {:else}
        <div class="space-y-4">
          <div>
            <label for="retentionDays" class="block text-sm text-slate-300 mb-1">
              Auto-delete after (days)
            </label>
            <input
              id="retentionDays"
              type="number"
              bind:value={retentionDays}
              min="1"
              max="3650"
              placeholder="Leave empty for indefinite"
              class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-emerald-500"
            />
            <p class="text-slate-500 text-xs mt-1">
              {retentionDays
                ? `Submissions older than ${retentionDays} days will be permanently deleted.`
                : 'No auto-deletion — submissions are retained indefinitely.'}
            </p>
          </div>

          {#if !retentionDays}
            <div class="bg-amber-900/40 border border-amber-700 rounded-lg p-3">
              <p class="text-amber-400 text-xs">
                ⚠️ We recommend setting a retention policy to minimize data exposure risk.
                A 90-day or 180-day window is common for most organizations.
              </p>
            </div>
          {/if}

          <div class="flex gap-2">
            <button
              onclick={saveRetention}
              disabled={retentionSaving}
              class="bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer"
            >
              {retentionSaving ? 'Saving...' : 'Save Retention Policy'}
            </button>
          </div>
        </div>
      {/if}
    </div>

    <!-- Notifications Card (Webhook + Email) -->
    <div class="bg-slate-800 rounded-lg p-6 shadow-xl mt-6">
      <h2 class="text-lg font-semibold text-white mb-4">
        New Submission Notifications
      </h2>

      <p class="text-slate-400 text-sm mb-4">
        Get notified when a new anonymous submission arrives.
        Only submission ID, timestamp, and portal slug are sent — never message content.
      </p>

      {#if notifMessage}
        <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-3 mb-4">
          <p class="text-emerald-400 text-sm">{notifMessage}</p>
        </div>
      {/if}
      {#if notifError}
        <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
          <p class="text-red-400 text-sm">{notifError}</p>
        </div>
      {/if}

      {#if notifLoading}
        <p class="text-slate-400 text-sm">Loading...</p>
      {:else}
        <div class="space-y-4">
          <!-- Webhook URL -->
          <div>
            <label for="webhookURL" class="block text-sm text-slate-300 mb-1">
              Webhook URL (optional)
            </label>
            <input
              id="webhookURL"
              type="url"
              bind:value={webhookURL}
              placeholder="https://your-service.com/webhook"
              class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
            <p class="text-slate-500 text-xs mt-1">
              POST payload with submission_id, timestamp, and portal_slug. Private/internal IPs are blocked.
            </p>
          </div>

          <!-- Notification Email -->
          <div>
            <label for="notifEmail" class="block text-sm text-slate-300 mb-1">
              Notification Email (optional)
            </label>
            <input
              id="notifEmail"
              type="email"
              bind:value={notificationEmail}
              placeholder="alerts@your-org.com"
              class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
            <p class="text-slate-500 text-xs mt-1">
              Metadata-only email (no message content). Requires SMTP configuration on the server.
            </p>
          </div>

          <div class="bg-slate-700/50 rounded-lg p-3">
            <p class="text-slate-400 text-xs">
              Both notifications are metadata-only: submission ID, timestamp, and portal slug.
              Message content is never included — the server cannot decrypt it.
            </p>
          </div>

          <button
            onclick={saveNotifications}
            disabled={notifSaving}
            class="bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer"
          >
            {notifSaving ? 'Saving...' : 'Save Notification Settings'}
          </button>
        </div>
      {/if}
    </div>
  </div>
</div>