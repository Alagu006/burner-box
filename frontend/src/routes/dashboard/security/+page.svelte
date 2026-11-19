<script>
  import { API_URL } from '$lib/api';
  import { logout } from '$lib/auth';
  import {
    generateKeyPair,
    encryptForRecipient,
    decryptFromSender,
    getStoredPrivateKey,
    getCachedDerivedKey,
    validatePGPPublicKey,
  } from '$lib/crypto';

  let token = $state('');
  let qrCode = $state('');
  let secret = $state('');
  let code = $state('');
  let message = $state('');
  let error = $state('');
  let totpEnabled = $state(false);
  let loading = $state(true);
  let setupMode = $state(false);

  // Scheme and Key rotation state
  let orgEncryptionScheme = $state('libsodium'); // 'libsodium' | 'pgp'
  let targetScheme = $state('libsodium');
  let newPgpKey = $state('');
  let pgpValidation = $state(null);
  let rotating = $state(false);
  let rotationProgress = $state('');
  let rotationError = $state('');
  let rotationSuccessMessage = $state('');

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

  // User role state
  let userRole = $state('admin');

  // Account deletion state
  let deleteModalOpen = $state(false);
  let deletePassword = $state('');
  let deleteTotpCode = $state('');
  let deleteConfirmationText = $state('');
  let deleteLoading = $state(false);
  let deleteError = $state('');

  function openDeleteModal() {
    deletePassword = '';
    deleteTotpCode = '';
    deleteConfirmationText = '';
    deleteError = '';
    deleteModalOpen = true;
  }

  function closeDeleteModal() {
    if (deleteLoading) return;
    deleteModalOpen = false;
  }

  async function loadUserRole() {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (resp.ok) {
        const data = await resp.json();
        userRole = data.role || 'admin';
      }
    } catch { /* ignore */ }
  }

  async function handleDeleteAccount() {
    if (!deletePassword) {
      deleteError = 'Password is required to confirm deletion.';
      return;
    }
    if (totpEnabled && !deleteTotpCode.trim()) {
      deleteError = 'TOTP authentication code is required.';
      return;
    }
    if (deleteConfirmationText.trim().toUpperCase() !== 'DELETE') {
      deleteError = 'Please type DELETE in all caps to confirm.';
      return;
    }

    deleteLoading = true;
    deleteError = '';

    try {
      const res = await fetch(`${API_URL}/api/v1/dashboard/account`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          password: deletePassword,
          code: totpEnabled ? deleteTotpCode.trim() : undefined,
        }),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        deleteError = data.error || 'Failed to delete organization account.';
        deleteLoading = false;
        return;
      }

      // Hard-delete succeeded! Clear session and local storage
      localStorage.removeItem('burnerbox_token');
      localStorage.removeItem('burnerbox_org');
      localStorage.removeItem('burnerbox_private_key');
      localStorage.removeItem('burnerbox_role');
      // Redirect to login with deleted notification
      window.location.href = '/login?deleted=true';
    } catch (err) {
      deleteError = err.message || 'Network error deleting account.';
      deleteLoading = false;
    }
  }

  $effect(() => {
    token = localStorage.getItem('burnerbox_token') || '';
    if (!token) {
      logout('', '/login');
      return;
    }
    const orgStored = localStorage.getItem('burnerbox_org');
    if (orgStored) {
      try {
        const parsed = JSON.parse(orgStored);
        if (parsed.encryption_scheme) {
          orgEncryptionScheme = parsed.encryption_scheme;
          targetScheme = parsed.encryption_scheme;
        }
      } catch {}
    }
    check2FAStatus();
    loadUserRole();
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
    if (response.status === 401) {
      await logout(token);
      return {};
    }
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

  async function handlePGPKeyValidation() {
    if (!newPgpKey.trim()) {
      pgpValidation = null;
      return;
    }
    pgpValidation = await validatePGPPublicKey(newPgpKey);
  }

  async function rotateKeys() {
    rotationError = '';
    rotationSuccessMessage = '';

    if (targetScheme === 'pgp') {
      if (!newPgpKey.trim()) {
        rotationError = 'Please paste an ASCII-armored PGP public key.';
        return;
      }
      const val = await validatePGPPublicKey(newPgpKey);
      if (!val.valid) {
        rotationError = 'Invalid PGP public key: ' + val.error;
        return;
      }

      const confirmed = confirm(
        'SWITCH TO PGP WARNING:\n\n' +
        'This will update your organization to use PGP encryption with your provided public key.\n\n' +
        'Your PGP private key is NOT stored in BurnerBox. You will need to import it into memory each session to decrypt new tips.\n\n' +
        'Continue?'
      );
      if (!confirmed) return;

      rotating = true;
      rotationProgress = 'Updating public key and encryption scheme on server...';

      try {
        const res = await fetch(`${API_URL}/api/v1/dashboard/public-key`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            public_key: newPgpKey.trim(),
            encryption_scheme: 'pgp',
          }),
        });

        if (!res.ok) {
          const data = await res.json();
          rotationError = data.error || 'Failed to update public key on server';
          rotating = false;
          return;
        }

        // PGP private keys are managed outside BurnerBox
        localStorage.removeItem('burnerbox_private_key');
        const orgStored = localStorage.getItem('burnerbox_org');
        if (orgStored) {
          try {
            const org = JSON.parse(orgStored);
            org.encryption_scheme = 'pgp';
            org.public_key = newPgpKey.trim();
            localStorage.setItem('burnerbox_org', JSON.stringify(org));
          } catch {}
        }

        orgEncryptionScheme = 'pgp';
        rotationSuccessMessage = 'Successfully switched to PGP encryption scheme!';
        newPgpKey = '';
        pgpValidation = null;
      } catch (err) {
        rotationError = 'Failed to update: ' + err.message;
      }

      rotating = false;
      rotationProgress = '';
      return;
    }

    // Libsodium flow
    const confirmed = confirm(
      'KEY ROTATION WARNING:\n\n' +
      'This will generate a new libsodium encryption keypair and re-encrypt all existing ' +
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
      if (!oldPrivateKey && orgEncryptionScheme === 'libsodium') {
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
        body: JSON.stringify({
          public_key: newKeyPair.publicKey,
          encryption_scheme: 'libsodium',
        }),
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

      let reencrypted = 0;
      let skipped = 0;

      if (listRes.ok && oldPrivateKey) {
        const listData = await listRes.json();
        const subs = listData.submissions || [];

        for (let i = 0; i < subs.length; i++) {
          const sub = subs[i];
          rotationProgress = `Re-encrypting submission ${i + 1}/${subs.length}...`;

          if (!sub.encrypted_message || !sub.encryption_meta) {
            skipped++;
            continue;
          }

          try {
            const meta = JSON.parse(sub.encryption_meta);
            if (meta.scheme === 'pgp') {
              skipped++;
              continue;
            }

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
              scheme: 'libsodium',
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
      }

      // Store new private key encrypted in localStorage using the cached derived key.
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

      const orgStored = localStorage.getItem('burnerbox_org');
      if (orgStored) {
        try {
          const org = JSON.parse(orgStored);
          org.encryption_scheme = 'libsodium';
          org.public_key = newKeyPair.publicKey;
          localStorage.setItem('burnerbox_org', JSON.stringify(org));
        } catch {}
      }

      orgEncryptionScheme = 'libsodium';
      rotationProgress = '';
      rotationSuccessMessage = `Key rotation complete. ${reencrypted} submission(s) re-encrypted, ${skipped} skipped.`;
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

      <!-- Key & Encryption Scheme Management Card -->
      <div class="bg-slate-800 rounded-lg p-6 shadow-xl">
        <div class="flex items-center justify-between mb-4 flex-wrap gap-2">
          <h2 class="text-lg font-semibold text-white">
            🔐 Encryption Scheme & Key Management
          </h2>
          {#if orgEncryptionScheme === 'pgp'}
            <span class="bg-blue-900/60 text-blue-300 border border-blue-500 px-2.5 py-1 rounded text-xs font-semibold">
              🛡️ Active: PGP (OpenPGP.js)
            </span>
          {:else}
            <span class="bg-emerald-900/60 text-emerald-300 border border-emerald-500 px-2.5 py-1 rounded text-xs font-semibold">
              ⚡ Active: libsodium (E2EE)
            </span>
          {/if}
        </div>

        <!-- Trade-off Explainer Card -->
        <div class="bg-slate-900/80 border border-slate-700 rounded-lg p-4 mb-5 text-xs text-slate-300 space-y-2">
          <p class="font-semibold text-white text-sm mb-1">⚖️ Encryption Scheme Trade-offs:</p>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
            <div class="bg-slate-800/80 p-3 rounded border border-emerald-500/30">
              <span class="text-emerald-400 font-bold block mb-1">⚡ libsodium (Recommended for most)</span>
              <p class="text-slate-400 leading-relaxed">
                <strong>Pros:</strong> Fully automated zero-friction key generation and password-derived local storage encryption.<br/>
                <strong>Trade-off:</strong> BurnerBox-specific cryptographic envelope.
              </p>
            </div>
            <div class="bg-slate-800/80 p-3 rounded border border-blue-500/30">
              <span class="text-blue-400 font-bold block mb-1">🛡️ PGP / GPG (Air-gapped & Interoperable)</span>
              <p class="text-slate-400 leading-relaxed">
                <strong>Pros:</strong> Interoperable with standard PGP tools (Thunderbird, GPG CLI, YubiKeys). Private key is never stored in BurnerBox.<br/>
                <strong>Trade-off:</strong> Requires manual in-memory private key import per dashboard session.
              </p>
            </div>
          </div>
        </div>

        <p class="text-slate-400 text-sm mb-4">
          Choose which cryptographic scheme to enforce for new anonymous submissions:
        </p>

        <!-- Scheme Selector -->
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
          <button
            type="button"
            onclick={() => { targetScheme = 'libsodium'; }}
            class="p-3 rounded-lg border text-left transition cursor-pointer {targetScheme === 'libsodium' ? 'bg-emerald-950/60 border-emerald-500 text-white ring-1 ring-emerald-500' : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600'}"
          >
            <div class="font-bold text-sm text-emerald-400 mb-1">⚡ libsodium Keypair</div>
            <p class="text-xs text-slate-400">Generate fresh browser keypair and re-encrypt tips.</p>
          </button>

          <button
            type="button"
            onclick={() => { targetScheme = 'pgp'; }}
            class="p-3 rounded-lg border text-left transition cursor-pointer {targetScheme === 'pgp' ? 'bg-blue-950/60 border-blue-500 text-white ring-1 ring-blue-500' : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600'}"
          >
            <div class="font-bold text-sm text-blue-400 mb-1">🛡️ PGP Public Key</div>
            <p class="text-xs text-slate-400">Paste your existing ASCII-armored PGP key.</p>
          </button>
        </div>

        <!-- PGP Key Input (if target is PGP) -->
        {#if targetScheme === 'pgp'}
          <div class="mb-4 bg-slate-900/60 p-3 rounded-lg border border-slate-700">
            <label for="newPgpKey" class="block text-xs font-semibold text-slate-300 mb-1">
              Paste ASCII-Armored PGP Public Key:
            </label>
            <textarea
              id="newPgpKey"
              bind:value={newPgpKey}
              oninput={handlePGPKeyValidation}
              rows="4"
              placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;...&#10;-----END PGP PUBLIC KEY BLOCK-----"
              class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-emerald-400 font-mono text-xs placeholder-slate-600 focus:outline-none focus:border-blue-500 resize-none"
            ></textarea>
            {#if pgpValidation}
              {#if pgpValidation.valid}
                <p class="text-xs text-emerald-400 mt-1">
                  ✅ Valid PGP Key (ID: {pgpValidation.keyID?.substring(0, 8)})
                </p>
              {:else}
                <p class="text-xs text-red-400 mt-1">
                  ❌ Invalid: {pgpValidation.error}
                </p>
              {/if}
            {/if}
          </div>
        {/if}

        {#if rotationError}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{rotationError}</p>
          </div>
        {/if}

        {#if rotationSuccessMessage}
          <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-3 mb-4">
            <p class="text-emerald-400 text-sm">✅ {rotationSuccessMessage}</p>
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
          class="bg-yellow-600 hover:bg-yellow-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer font-medium"
        >
          {rotating ? 'Updating...' : targetScheme === 'pgp' ? 'Save PGP Public Key' : 'Rotate libsodium Keys'}
        </button>

        <p class="text-slate-500 text-xs mt-3">
          {#if targetScheme === 'pgp'}
            Submissions submitted after switching will be encrypted with your PGP key.
          {:else}
            Team members will need to re-login after key rotation.
          {/if}
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

    <!-- Danger Zone Card: Permanent Account Deletion -->
    <div class="bg-red-950/20 border-2 border-red-900/60 rounded-xl p-6 shadow-xl mt-8">
      <div class="flex items-start justify-between gap-4">
        <div>
          <div class="flex items-center gap-2 mb-2">
            <span class="inline-flex items-center justify-center w-6 h-6 rounded-full bg-red-900/60 text-red-400 font-bold text-xs">⚠️</span>
            <h2 class="text-lg font-bold text-red-300">
              Danger Zone: Delete Organization Account
            </h2>
          </div>
          <p class="text-slate-300 text-sm mb-3">
            Permanently delete your entire organization and all associated data. This action is irreversible.
          </p>
          <div class="text-xs text-red-200/80 space-y-1 bg-red-950/40 p-3 rounded-lg border border-red-900/40">
            <p class="font-semibold text-red-300">What will be permanently erased:</p>
            <ul class="list-disc list-inside space-y-0.5 text-slate-300 ml-1">
              <li>All encrypted submissions and uploaded attachments from disk</li>
              <li>All reply messages, internal notes, and secure thread records</li>
              <li>All cryptographic Merkle audit batches and leaves</li>
              <li>All active user sessions, invitations, and team member accounts</li>
              <li>Dead man's switch configurations, retention policies, and settings</li>
            </ul>
          </div>
        </div>
      </div>

      <div class="mt-6 flex items-center justify-between pt-4 border-t border-red-900/40">
        <div>
          {#if userRole !== 'admin'}
            <p class="text-xs text-amber-400">Only organization administrators can delete the account.</p>
          {:else}
            <p class="text-xs text-slate-400">Once deleted, your data cannot be recovered by anyone, including BurnerBox operators.</p>
          {/if}
        </div>
        <button
          onclick={openDeleteModal}
          disabled={userRole !== 'admin'}
          class="bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium px-4 py-2 rounded-lg text-sm transition cursor-pointer shadow-lg shadow-red-950/50"
        >
          Delete Account
        </button>
      </div>
    </div>

    <!-- Permanent Deletion Confirmation Modal -->
    {#if deleteModalOpen}
      <div
        class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto"
        role="dialog"
        aria-modal="true"
        aria-labelledby="delete-account-title"
      >
        <div class="bg-slate-900 border-2 border-red-600/80 rounded-2xl max-w-lg w-full p-6 shadow-2xl text-white relative">
          <div class="flex items-center gap-3 text-red-400 mb-4 pb-3 border-b border-red-900/40">
            <div class="w-10 h-10 rounded-full bg-red-900/40 border border-red-600 flex items-center justify-center font-bold text-lg">
              ⚠️
            </div>
            <div>
              <h3 id="delete-account-title" class="text-lg font-bold text-white">Permanently Delete Account?</h3>
              <p class="text-xs text-red-300">This action CANNOT be undone.</p>
            </div>
          </div>

          <div class="space-y-4 text-sm text-slate-300 mb-6">
            <p>
              You are about to <strong class="text-red-400 font-semibold">hard-delete your organization and all tied records</strong>.
              All submissions, encrypted files on disk, replies, notes, Merkle leaves, team members, and settings will be permanently wiped.
            </p>

            {#if deleteError}
              <div class="bg-red-950/80 border border-red-500 rounded-lg p-3 text-red-200 text-xs">
                {deleteError}
              </div>
            {/if}

            <div>
              <label for="delete-password" class="block text-xs font-semibold text-slate-300 mb-1">
                Enter your admin password:
              </label>
              <input
                id="delete-password"
                type="password"
                bind:value={deletePassword}
                placeholder="Current password"
                disabled={deleteLoading}
                class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-red-500 text-sm"
              />
            </div>

            {#if totpEnabled}
              <div>
                <label for="delete-totp" class="block text-xs font-semibold text-slate-300 mb-1">
                  Enter 6-digit 2FA / TOTP Code:
                </label>
                <input
                  id="delete-totp"
                  type="text"
                  inputmode="numeric"
                  maxlength="6"
                  bind:value={deleteTotpCode}
                  placeholder="123456"
                  disabled={deleteLoading}
                  class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white font-mono tracking-widest text-center focus:outline-none focus:border-red-500 text-sm"
                />
              </div>
            {/if}

            <div>
              <label for="delete-confirm-text" class="block text-xs font-semibold text-slate-300 mb-1">
                To confirm, type <span class="font-mono text-red-400 font-bold">DELETE</span> below:
              </label>
              <input
                id="delete-confirm-text"
                type="text"
                bind:value={deleteConfirmationText}
                placeholder="DELETE"
                disabled={deleteLoading}
                class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-red-500 text-sm font-mono"
              />
            </div>
          </div>

          <div class="flex justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onclick={closeDeleteModal}
              disabled={deleteLoading}
              class="px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-300 text-sm rounded-lg transition cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="button"
              onclick={handleDeleteAccount}
              disabled={deleteLoading || !deletePassword || (totpEnabled && !deleteTotpCode.trim()) || deleteConfirmationText.trim().toUpperCase() !== 'DELETE'}
              class="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed text-white font-medium text-sm rounded-lg transition cursor-pointer shadow-lg shadow-red-950/60"
            >
              {deleteLoading ? 'Deleting Account...' : 'Permanently Delete Everything'}
            </button>
          </div>
        </div>
      </div>
    {/if}
  </div>
</div>