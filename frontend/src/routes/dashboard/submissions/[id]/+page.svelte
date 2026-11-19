<script>
  import { page } from '$app/stores';
  import {
    decryptFromSender,
    encryptForRecipient,
    decryptFile,
    getStoredPrivateKey,
    decryptWithPGP,
    decryptFileWithPGP,
    getTransientPGPPrivateKey,
    setTransientPGPPrivateKey,
  } from '$lib/crypto';
  import { API_URL } from '$lib/api';
  import { renderMarkdown } from '$lib/markdown';
  import { logout } from '$lib/auth';

  let token = $state('');
  let submissionData = $state(null);
  let loading = $state(true);
  let decrypting = $state(false);
  let error = $state('');
  let decryptionError = $state('');
  let decryptedMessage = $state('');
  let id = $state('');
  let role = $state('reader');
  let teamMembers = $state([]);

  // PGP Transient Key State
  let isPGPSubmission = $state(false);
  let decryptedCustomFields = $state(null);
  let showPGPModal = $state(false);
  let pgpKeyInput = $state('');
  let pgpPassphraseInput = $state('');
  let pgpImportError = $state('');

  // Thread state
  let timeline = $state([]);
  let timelineDecrypting = $state(false);
  let timelineErrors = $state({});
  let threadText = $state('');
  let sendingThread = $state(false);
  let threadError = $state('');
  let threadSuccess = $state(false);

  // Threaded notes state
  let notes = $state([]);
  let noteText = $state('');
  let replyToNoteId = $state(null);
  let sendingNote = $state(false);
  let noteError = $state('');

  // Activity state
  let activities = $state([]);

  // File state
  let files = $state([]);
  let downloadingFileId = $state('');

  $effect(() => {
    token = localStorage.getItem('burnerbox_token') || '';
    id = $page.params.id;
    if (token && id) {
      loadSubmission();
    } else if (!token) {
      logout('', '/login');
    }
  });

  async function loadSubmission() {
    loading = true;
    error = '';
    decryptionError = '';
    decryptedMessage = '';
    timeline = [];
    files = [];

    try {
      const response = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });

      if (response.status === 401) {
        await logout(token);
        return;
      }

      const data = await response.json();
      if (response.ok) {
        submissionData = data;
        await decryptSubmissionIfEncrypted(data);
        await loadTimeline();
        await loadFiles();
        await loadNotes();
        await loadActivity();
        await loadRoleAndTeam();
      } else {
        error = data.error || 'Not found';
      }
    } catch {
      error = 'Network error';
    }
    loading = false;
  }

  async function decryptSubmissionIfEncrypted(data) {
    const sub = data.submission;
    if (!sub.encrypted_message) return;

    let scheme = 'libsodium';
    if (sub.encryption_meta) {
      try {
        const parsed = JSON.parse(sub.encryption_meta);
        if (parsed.scheme) scheme = parsed.scheme;
      } catch {}
    }
    if (sub.encrypted_message.includes('-----BEGIN PGP MESSAGE-----')) {
      scheme = 'pgp';
    }

    isPGPSubmission = scheme === 'pgp';
    decrypting = true;
    decryptionError = '';

    try {
      if (isPGPSubmission) {
        const transient = getTransientPGPPrivateKey();
        if (!transient || !transient.privateKey) {
          decryptionError = 'PGP private key required for this session. Please import your private key below.';
          showPGPModal = true;
          decrypting = false;
          return;
        }

        const result = await decryptWithPGP(
          sub.encrypted_message,
          transient.privateKey,
          transient.passphrase
        );
        unpackDecryptedPayload(result);
      } else {
        // Libsodium flow
        const privateKey = await getStoredPrivateKey();
        if (!privateKey) {
          decryptionError = 'Private key not available. Please login with your password to decrypt submissions.';
          decrypting = false;
          return;
        }

        const meta = JSON.parse(sub.encryption_meta);
        const result = await decryptFromSender(
          {
            ciphertext: sub.encrypted_message,
            nonce: meta.nonce,
            encryptedKey: meta.encryptedKey,
            boxNonce: meta.boxNonce,
            senderPublicKey: meta.senderPublicKey,
          },
          privateKey
        );
        unpackDecryptedPayload(result);
      }
    } catch (err) {
      decryptionError = 'Decryption failed: ' + (err.message || 'wrong key or corrupted data.');
    }
    decrypting = false;
  }

  function unpackDecryptedPayload(rawResult) {
    let mainMsg = rawResult;
    let customFieldsMap = null;
    try {
      const parsed = JSON.parse(rawResult);
      if (parsed && typeof parsed === 'object') {
        if (parsed.main_message !== undefined || parsed.custom_fields !== undefined) {
          mainMsg = parsed.main_message || '';
          customFieldsMap = parsed.custom_fields || null;
        }
      }
    } catch {
      // Not JSON, display raw plain text
    }
    decryptedMessage = mainMsg;
    decryptedCustomFields = customFieldsMap;
  }

  async function handleImportPGPKey(e) {
    if (e) e.preventDefault();
    pgpImportError = '';

    if (!pgpKeyInput.trim()) {
      pgpImportError = 'Please paste your ASCII-armored PGP private key.';
      return;
    }

    try {
      // Test decryption with the entered key to verify it immediately
      setTransientPGPPrivateKey(pgpKeyInput, pgpPassphraseInput);
      if (submissionData) {
        await decryptSubmissionIfEncrypted(submissionData);
        await decryptTimeline();
      }
      if (!decryptionError) {
        showPGPModal = false;
      } else {
        pgpImportError = decryptionError;
      }
    } catch (err) {
      pgpImportError = 'Failed to load PGP key: ' + err.message;
    }
  }

  async function loadTimeline() {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/messages`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (!resp.ok) return;
      const data = await resp.json();
      timeline = data.timeline || [];
      await decryptTimeline();
    } catch { /* skip */ }
  }

  async function decryptTimeline() {
    timelineDecrypting = true;
    const transient = getTransientPGPPrivateKey();
    const libsodiumKey = await getStoredPrivateKey();

    for (let i = 0; i < timeline.length; i++) {
      const entry = timeline[i];
      if (!entry.encrypted_text) continue;

      let scheme = 'libsodium';
      if (entry.encryption_meta) {
        try {
          const parsed = JSON.parse(entry.encryption_meta);
          if (parsed.scheme) scheme = parsed.scheme;
        } catch {}
      }
      if (entry.encrypted_text.includes('-----BEGIN PGP MESSAGE-----')) {
        scheme = 'pgp';
      }

      try {
        if (scheme === 'pgp') {
          if (!transient || !transient.privateKey) {
            timelineErrors[i] = 'PGP private key required for session';
            continue;
          }
          entry._decryptedText = await decryptWithPGP(entry.encrypted_text, transient.privateKey, transient.passphrase);
        } else {
          if (!libsodiumKey) {
            timelineErrors[i] = 'Private key unavailable';
            continue;
          }
          const meta = JSON.parse(entry.encryption_meta);
          const decrypted = await decryptFromSender(
            {
              ciphertext: entry.encrypted_text,
              nonce: meta.nonce,
              encryptedKey: meta.encryptedKey,
              boxNonce: meta.boxNonce,
              senderPublicKey: meta.senderPublicKey,
            },
            libsodiumKey
          );
          entry._decryptedText = decrypted;
        }
      } catch {
        timelineErrors[i] = 'Failed to decrypt';
      }
    }
    timelineDecrypting = false;
  }

  async function sendThreadReply() {
    if (!threadText.trim()) return;
    sendingThread = true;
    threadError = '';
    threadSuccess = false;

    try {
      const sub = submissionData?.submission;
      if (!sub?.reply_public_key) {
        threadError = 'Cannot reply: Submitter did not enable replies';
        sendingThread = false;
        return;
      }

      const encResult = await encryptForRecipient(threadText, sub.reply_public_key);
      const encryptionMeta = {
        nonce: encResult.nonce,
        encryptedKey: encResult.encryptedKey,
        boxNonce: encResult.boxNonce,
        senderPublicKey: encResult.senderPublicKey,
      };

      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/reply`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          encrypted_message: encResult.ciphertext,
          encryption_meta: JSON.stringify(encryptionMeta),
        }),
      });

      if (resp.ok) {
        threadText = '';
        threadSuccess = true;
        await loadTimeline();
        await loadActivity();
      } else {
        const d = await resp.json();
        threadError = d.error || 'Failed to send reply';
      }
    } catch {
      threadError = 'Network error';
    }
    sendingThread = false;
  }

  async function loadFiles() {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/files`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (resp.ok) {
        const d = await resp.json();
        files = d.files || [];
      }
    } catch { /* skip */ }
  }

  async function loadRoleAndTeam() {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (resp.ok) {
        const data = await resp.json();
        role = data.role || 'reader';
      }
      const tResp = await fetch(`${API_URL}/api/v1/dashboard/team/`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (tResp.ok) {
        const tData = await tResp.json();
        teamMembers = tData.members || [];
      }
    } catch { /* skip */ }
  }

  async function loadNotes() {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/notes`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (resp.ok) {
        const d = await resp.json();
        notes = d.notes || [];
      }
    } catch { /* skip */ }
  }

  async function sendNote() {
    if (!noteText.trim()) return;
    sendingNote = true;
    noteError = '';

    try {
      const body = { note: noteText };
      if (replyToNoteId) body.parent_id = replyToNoteId;

      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/notes`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (resp.ok) {
        noteText = '';
        replyToNoteId = null;
        await loadNotes();
        await loadActivity();
      } else {
        const d = await resp.json();
        noteError = d.error || 'Failed';
      }
    } catch { noteError = 'Network error'; }
    sendingNote = false;
  }

  async function loadActivity() {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/activity`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (resp.ok) { const d = await resp.json(); activities = d.activities || []; }
    } catch { /* skip */ }
  }

  async function updatePriorityLocal(priority) {
    if (!submissionData?.submission) return;
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ priority }),
      });
      if (resp.ok) submissionData.submission.priority = priority;
    } catch { /* skip */ }
  }

  async function assignSubmissionLocal(memberId) {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/assign`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ assigned_to: memberId || null }),
      });
      if (resp.ok) await loadSubmission();
    } catch { /* skip */ }
  }

  async function downloadFile(fileId, fileName) {
    downloadingFileId = fileId;
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/files/${fileId}`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        alert('Download failed: ' + (data.error || 'Unknown error'));
        downloadingFileId = '';
        return;
      }

      let blob;
      const clientMeta = resp.headers.get('X-Client-Encryption-Meta');
      if (clientMeta) {
        try {
          const metaMap = JSON.parse(clientMeta);
          const fileMeta = metaMap[fileName];
          const ciphertext = await resp.arrayBuffer();

          if (!fileMeta) {
            blob = new Blob([ciphertext]);
          } else if (fileMeta.scheme === 'pgp' || isPGPSubmission) {
            const transient = getTransientPGPPrivateKey();
            if (!transient?.privateKey) {
              alert('Cannot decrypt file: PGP private key not loaded in this session. Please import your PGP key above.');
              downloadingFileId = '';
              return;
            }
            const decrypted = await decryptFileWithPGP(
              new TextDecoder().decode(ciphertext),
              transient.privateKey,
              transient.passphrase
            );
            blob = new Blob([decrypted]);
          } else {
            const privateKey = await getStoredPrivateKey();
            if (!privateKey) {
              alert('Cannot decrypt file: private key not found. Please login with your password.');
              downloadingFileId = '';
              return;
            }
            const decrypted = await decryptFile(
              {
                ciphertext: new TextDecoder().decode(ciphertext),
                nonce: fileMeta.nonce,
                encryptedKey: fileMeta.encryptedKey,
                boxNonce: fileMeta.boxNonce,
                senderPublicKey: fileMeta.senderPublicKey,
              },
              privateKey
            );
            blob = new Blob([decrypted]);
          }
        } catch (e) {
          blob = await resp.blob().catch(() => new Blob([]));
        }
      } else {
        blob = await resp.blob();
      }

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Network error during download');
    }
    downloadingFileId = '';
  }

  function formatDate(dateString) {
    if (!dateString) return '';
    return new Date(dateString).toLocaleString('en-IN', {
      day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  }

  function formatSize(bytes) {
    if (!bytes) return '';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }
</script>

<div class="min-h-screen bg-slate-900 p-4">
  <div class="max-w-3xl mx-auto">
    <a href="/dashboard/submissions" class="text-slate-400 hover:text-white text-sm mb-4 inline-block">
      ← Back to Submissions
    </a>

    {#if loading}
      <p class="text-slate-400">Loading...</p>
    {:else if error}
      <div class="bg-red-900/50 border border-red-500 rounded-lg p-6">
        <p class="text-red-400">{error}</p>
      </div>
    {:else if submissionData}
      <div class="bg-slate-800 rounded-lg p-6 shadow-xl">
        <div class="flex items-center justify-between mb-4 flex-wrap gap-2">
          <h1 class="text-xl font-bold text-white flex items-center gap-2">
            <span>{submissionData.submission.anonymous_name}</span>
            {#if isPGPSubmission}
              <span class="bg-blue-900/60 text-blue-400 border border-blue-600 px-2 py-0.5 rounded text-xs font-normal">
                🛡️ PGP Encrypted
              </span>
            {:else}
              <span class="bg-emerald-900/60 text-emerald-400 border border-emerald-600 px-2 py-0.5 rounded text-xs font-normal">
                ⚡ libsodium Encrypted
              </span>
            {/if}
          </h1>

          {#if isPGPSubmission}
            <button
              onclick={() => { showPGPModal = !showPGPModal; }}
              class="bg-slate-700 hover:bg-slate-600 text-blue-300 text-xs px-3 py-1.5 rounded transition cursor-pointer"
            >
              🔑 {getTransientPGPPrivateKey() ? 'PGP Key Loaded (Change)' : 'Import PGP Key'}
            </button>
          {/if}
        </div>

        <!-- PGP Transient Key Import Card -->
        {#if isPGPSubmission && showPGPModal}
          <div class="bg-blue-950/60 border border-blue-500/70 rounded-lg p-4 mb-4">
            <h3 class="text-sm font-bold text-blue-300 mb-1 flex items-center gap-2">
              <span>🛡️ Transient PGP Session Key</span>
            </h3>
            <p class="text-xs text-slate-300 mb-3 leading-relaxed">
              BurnerBox never stores your PGP private key. Paste your ASCII-armored private key below to decrypt this tip. It is held <strong>in browser memory only</strong> and vanishes on tab close.
            </p>

            {#if pgpImportError}
              <div class="bg-red-900/50 border border-red-500 rounded p-2 mb-3">
                <p class="text-red-300 text-xs">{pgpImportError}</p>
              </div>
            {/if}

            <form onsubmit={handleImportPGPKey} class="space-y-3">
              <div>
                <label for="pgpPrivKey" class="block text-xs font-semibold text-slate-300 mb-1">
                  ASCII-Armored PGP Private Key:
                </label>
                <textarea
                  id="pgpPrivKey"
                  bind:value={pgpKeyInput}
                  rows="4"
                  placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----&#10;...&#10;-----END PGP PRIVATE KEY BLOCK-----"
                  class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-emerald-400 font-mono text-xs placeholder-slate-600 focus:outline-none focus:border-blue-500 resize-none"
                ></textarea>
              </div>

              <div>
                <label for="pgpPass" class="block text-xs font-semibold text-slate-300 mb-1">
                  Passphrase (leave empty if none):
                </label>
                <input
                  id="pgpPass"
                  type="password"
                  bind:value={pgpPassphraseInput}
                  placeholder="Private key passphrase"
                  class="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-white text-xs placeholder-slate-600 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div class="flex gap-2">
                <button
                  type="submit"
                  class="bg-blue-600 hover:bg-blue-700 text-white text-xs px-4 py-2 rounded font-medium transition cursor-pointer"
                >
                  🔓 Decrypt in Session
                </button>
                <button
                  type="button"
                  onclick={() => { showPGPModal = false; }}
                  class="bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs px-3 py-2 rounded transition cursor-pointer"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        {/if}

        {#if decryptionError}
          <div class="bg-red-900/30 border border-red-500 rounded-lg p-4 mb-4">
            <p class="text-red-400 text-sm font-medium">🔒 {decryptionError}</p>
          </div>
        {/if}

        <!-- Main message -->
        {#if decryptedMessage}
          <pre class="text-white whitespace-pre-wrap bg-slate-700 p-4 rounded-lg mb-4">{decryptedMessage}</pre>
        {:else if submissionData.submission.encrypted_message}
          {#if decrypting}
            <div class="bg-slate-700 p-4 rounded-lg mb-4"><p class="text-emerald-400 text-sm">🔐 Decrypting...</p></div>
          {:else if !decryptionError}
            <div class="bg-slate-700 p-4 rounded-lg mb-4"><p class="text-slate-500 italic text-sm">🔒 Encrypted message</p></div>
          {/if}
        {:else if submissionData.submission.message_text}
          <pre class="text-white whitespace-pre-wrap bg-slate-700 p-4 rounded-lg mb-4">{submissionData.submission.message_text}</pre>
        {:else}
          <p class="text-slate-500 italic mb-4">(No message)</p>
        {/if}

        <!-- Structured Custom Field Responses (Decrypted) -->
        {#if decryptedCustomFields && Object.keys(decryptedCustomFields).length > 0}
          <div class="bg-slate-700/60 border border-slate-600/80 rounded-lg p-4 mb-4 space-y-3">
            <h4 class="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
              <span>📋 Additional Submitter Details (Decrypted)</span>
            </h4>
            <div class="grid grid-cols-1 gap-2.5">
              {#each Object.entries(decryptedCustomFields) as [fieldLabel, fieldVal]}
                <div class="bg-slate-800/90 rounded-md p-3 border border-slate-700">
                  <p class="text-xs text-slate-400 font-medium mb-1">{fieldLabel}</p>
                  <p class="text-xs text-white whitespace-pre-wrap font-sans">{fieldVal}</p>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Files -->
        {#if files.length > 0}
          <div class="mb-4">
            <h3 class="text-sm font-medium text-slate-300 mb-2">Attachments ({files.length})</h3>
            <div class="space-y-1">
              {#each files as file}
                <div class="flex items-center gap-3 bg-slate-700/50 rounded-lg p-2">
                  <span class="text-slate-400 text-xs flex-1 truncate">📎 {file.file_name}</span>
                  <span class="text-slate-500 text-xs">{formatSize(file.file_size)}</span>
                  <button
                    onclick={() => downloadFile(file.id, file.file_name)}
                    disabled={downloadingFileId === file.id}
                    class="text-emerald-400 hover:text-emerald-300 text-xs cursor-pointer disabled:opacity-50"
                  >
                    {downloadingFileId === file.id ? '⏳' : '⬇️'}
                  </button>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Thread Timeline -->
        <div class="border-t border-slate-700 mt-4 pt-4">
          <h3 class="text-sm font-medium text-slate-300 mb-3">Thread</h3>

          {#if timeline.length > 0}
            <div class="space-y-3 mb-4">
              {#each timeline as entry, i}
                <div class="rounded-lg p-3 {entry.sender_type === 'org' ? 'bg-emerald-900/20 border-l-2 border-emerald-500' : 'bg-blue-900/20 border-l-2 border-blue-400'}">
                  <div class="flex items-center gap-2 mb-1">
                    <span class="text-xs font-medium {entry.sender_type === 'org' ? 'text-emerald-400' : 'text-blue-300'}">
                      {entry.sender_type === 'org' ? '🏛️ You (Org)' : '👤 Submitter'}
                    </span>
                    <span class="text-slate-500 text-xs">·</span>
                    <span class="text-slate-500 text-xs">{formatDate(entry.created_at)}</span>
                  </div>
                  {#if entry._decryptedText}
                    <p class="text-white text-sm whitespace-pre-wrap">{entry._decryptedText}</p>
                  {:else if entry.encrypted_text}
                    {#if timelineErrors[i]}
                      <p class="text-red-400 text-sm">🔒 {timelineErrors[i]}</p>
                    {:else if timelineDecrypting}
                      <p class="text-slate-500 italic text-sm">🔐 Decrypting...</p>
                    {:else}
                      <p class="text-slate-500 italic text-sm">🔒 Encrypted</p>
                    {/if}
                  {:else}
                    <p class="text-white text-sm whitespace-pre-wrap">{entry.message_text}</p>
                  {/if}
                </div>
              {/each}
            </div>
          {:else}
            <p class="text-slate-500 text-sm italic mb-4">No thread messages yet</p>
          {/if}

          <!-- Reply form (for responder / admin) -->
          {#if role === 'admin' || role === 'responder'}
            {#if submissionData.submission.reply_public_key}
              <div class="space-y-2">
                <textarea
                  bind:value={threadText}
                  placeholder="Write an end-to-end encrypted reply to this submitter..."
                  rows="3"
                  class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 text-sm"
                ></textarea>
                {#if threadError}
                  <p class="text-red-400 text-xs">{threadError}</p>
                {/if}
                {#if threadSuccess}
                  <p class="text-emerald-400 text-xs">Reply sent and encrypted with submitter's key</p>
                {/if}
                <button
                  onclick={sendThreadReply}
                  disabled={sendingThread || !threadText.trim()}
                  class="bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium transition cursor-pointer"
                >
                  {sendingThread ? 'Encrypting & Sending...' : '💬 Send Encrypted Reply'}
                </button>
              </div>
            {:else}
              <p class="text-slate-500 text-xs italic">Submitter did not enable replies for this tip</p>
            {/if}
          {/if}
        </div>

        <!-- Internal Notes (Threaded) -->
        <div class="border-t border-slate-700 mt-6 pt-4">
          <h3 class="text-sm font-medium text-slate-300 mb-3">Internal Notes (Team Only)</h3>

          {#if notes.length > 0}
            <div class="space-y-3 mb-4">
              {#each notes as note}
                <div class="bg-slate-700/40 rounded-lg p-3">
                  <div class="flex items-center justify-between mb-1">
                    <span class="text-xs font-semibold text-emerald-400">{note.author_email || 'Team Member'}</span>
                    <span class="text-slate-500 text-xs">{formatDate(note.created_at)}</span>
                  </div>
                  <div class="text-slate-200 text-sm prose prose-invert max-w-none">
                    {@html renderMarkdown(note.note)}
                  </div>
                </div>
              {/each}
            </div>
          {:else}
            <p class="text-slate-500 text-sm italic mb-4">No internal notes yet</p>
          {/if}

          {#if role === 'admin' || role === 'responder'}
            <div class="space-y-2">
              <textarea
                bind:value={noteText}
                placeholder="Add an internal note (Markdown supported, safe HTML only)..."
                rows="2"
                class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 text-sm"
              ></textarea>
              {#if noteError}
                <p class="text-red-400 text-xs">{noteError}</p>
              {/if}
              <button
                onclick={sendNote}
                disabled={sendingNote || !noteText.trim()}
                class="bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white px-3 py-1.5 rounded text-xs transition cursor-pointer"
              >
                {sendingNote ? 'Adding...' : '📝 Add Note'}
              </button>
            </div>
          {/if}
        </div>

        <!-- Activity Log -->
        <div class="border-t border-slate-700 mt-6 pt-4">
          <h3 class="text-sm font-medium text-slate-300 mb-3">Activity Log</h3>
          {#if activities.length > 0}
            <div class="space-y-1 max-h-48 overflow-y-auto">
              {#each activities as act}
                <div class="text-xs text-slate-400 flex items-center justify-between py-1 border-b border-slate-800">
                  <span>{act.actor_email ? act.actor_email : 'System'} {act.action}</span>
                  <span class="text-slate-600">{formatDate(act.created_at)}</span>
                </div>
              {/each}
            </div>
          {:else}
            <p class="text-slate-500 text-xs italic">No activity recorded</p>
          {/if}
        </div>

      </div>
    {/if}
  </div>
</div>
