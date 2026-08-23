<script>
  import { page } from '$app/stores';
  import { decryptFromSender, encryptForRecipient, getStoredPrivateKey } from '$lib/crypto';
  import { API_URL } from '$lib/api';
  import { renderMarkdown } from '$lib/markdown';

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
      window.location.href = '/login';
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
        localStorage.removeItem('burnerbox_token');
        localStorage.removeItem('burnerbox_org');
        window.location.href = '/login';
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
    if (!sub.encrypted_message || !sub.encryption_meta) return;

    decrypting = true;
    try {
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
      decryptedMessage = result;
    } catch {
      decryptionError = 'Decryption failed — wrong key or corrupted data.';
    }
    decrypting = false;
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
    const privateKey = await getStoredPrivateKey();
    if (!privateKey) {
      timeline.forEach((entry, i) => {
        if (entry.encrypted_text) timelineErrors[i] = 'Private key unavailable';
      });
      return;
    }

    timelineDecrypting = true;

    for (let i = 0; i < timeline.length; i++) {
      const entry = timeline[i];
      if (!entry.encrypted_text || !entry.encryption_meta) continue;

      try {
        const meta = JSON.parse(entry.encryption_meta);
        const decrypted = await decryptFromSender(
          {
            ciphertext: entry.encrypted_text,
            nonce: meta.nonce,
            encryptedKey: meta.encryptedKey,
            boxNonce: meta.boxNonce,
            senderPublicKey: meta.senderPublicKey,
          },
          privateKey
        );
        entry._decryptedText = decrypted;
      } catch {
        timelineErrors[i] = 'Decryption failed';
      }
    }

    timelineDecrypting = false;
  }

  async function sendThreadMessage() {
    threadError = '';
    threadSuccess = false;

    if (!threadText.trim()) {
      threadError = 'Message cannot be empty';
      return;
    }

    sendingThread = true;

    try {
      const privateKey = await getStoredPrivateKey();
      if (!privateKey) {
        threadError = 'Private key unavailable. Login with your password first.';
        sendingThread = false;
        return;
      }

      // Encrypt for the submitter using their reply public key
      const sub = submissionData?.submission;
      if (!sub?.reply_public_key) {
        threadError = 'No reply public key on this submission';
        sendingThread = false;
        return;
      }

      const encrypted = await encryptForRecipient(threadText.trim(), sub.reply_public_key);

      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/messages`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          encrypted_text: encrypted.ciphertext,
          encryption_meta: JSON.stringify({
            nonce: encrypted.nonce,
            encryptedKey: encrypted.encryptedKey,
            boxNonce: encrypted.boxNonce,
            senderPublicKey: encrypted.senderPublicKey,
          }),
        }),
      });

      const data = await resp.json();

      if (!resp.ok) {
        threadError = data.error || 'Failed to send';
        sendingThread = false;
        return;
      }

      const newEntry = {
        id: data.msg_id,
        sender_type: 'org',
        encrypted_text: encrypted.ciphertext,
        encryption_meta: JSON.stringify({
          nonce: encrypted.nonce, encryptedKey: encrypted.encryptedKey,
          boxNonce: encrypted.boxNonce, senderPublicKey: encrypted.senderPublicKey,
        }),
        message_text: '',
        created_at: new Date().toISOString(),
        source: 'thread',
        _decryptedText: threadText.trim(),
      };
      timeline = [...timeline, newEntry];
      threadText = '';
      threadSuccess = true;
      setTimeout(() => { threadSuccess = false; }, 3000);

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
        const data = await resp.json();
        files = data.files || [];
      }
    } catch { /* skip */ }
  }

  async function loadRoleAndTeam() {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (resp.ok) { const d = await resp.json(); role = d.role || 'reader'; }
    } catch { /* skip */ }
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/team/`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (resp.ok) { const d = await resp.json(); teamMembers = d.members || []; }
    } catch { /* skip */ }
  }

  async function loadNotes() {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/notes`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (resp.ok) { const d = await resp.json(); notes = d.notes || []; }
    } catch { /* skip */ }
  }

  async function addNote() {
    if (!noteText.trim()) return;
    sendingNote = true;
    noteError = '';
    try {
      const body = { note: noteText.trim() };
      if (replyToNoteId) body.parent_note_id = replyToNoteId;
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/notes`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (resp.ok) {
        noteText = '';
        replyToNoteId = null;
        await loadNotes();
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
      if (!resp.ok) return;

      let blob;
      const clientMeta = resp.headers.get('X-Client-Encryption-Meta');
      if (clientMeta) {
        try {
          const { decryptFile, getStoredPrivateKey } = await import('$lib/crypto');
          const privateKey = await getStoredPrivateKey();
          if (!privateKey) {
            alert('Cannot decrypt file: private key not found. Please login with your password.');
            return;
          }
          const ciphertext = await resp.arrayBuffer();
          const metaMap = JSON.parse(clientMeta);
          const fileMeta = metaMap[fileName];
          if (!fileMeta) {
            blob = new Blob([ciphertext]);
          } else {
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
        } catch {
          const raw = await resp.blob();
          blob = raw;
        }
      } else {
        blob = await resp.blob();
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch { /* skip */ }
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
        <h1 class="text-xl font-bold text-white mb-4">
          {submissionData.submission.anonymous_name}
        </h1>

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
                  {:else if entry.message_text}
                    <p class="text-white text-sm whitespace-pre-wrap">{entry.message_text}</p>
                  {/if}
                </div>
              {/each}
            </div>
          {:else}
            <p class="text-slate-500 text-sm mb-4">No thread messages yet.</p>
          {/if}

          <!-- Org thread message form -->
          {#if submissionData.submission.has_reply_key}
            <div class="bg-slate-700/50 rounded-lg p-3">
              <label for="thread-msg" class="block text-xs text-slate-400 mb-1">Add a reply to the thread</label>
              <textarea
                id="thread-msg"
                bind:value={threadText}
                rows="2"
                maxlength="10000"
                class="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded-lg text-white text-sm placeholder-slate-400 focus:outline-none focus:border-emerald-500 resize-none"
                placeholder="Type an encrypted reply..."
              ></textarea>
              {#if threadError}
                <p class="text-red-400 text-xs mt-1">{threadError}</p>
              {/if}
              {#if threadSuccess}
                <p class="text-emerald-400 text-xs mt-1">✅ Sent</p>
              {/if}
              <button
                onclick={sendThreadMessage}
                disabled={sendingThread || !threadText.trim()}
                class="mt-2 bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white text-sm px-4 py-1.5 rounded-lg transition cursor-pointer"
              >
                {sendingThread ? 'Sending...' : '📤 Send Reply'}
              </button>
            </div>
          {:else}
            <p class="text-slate-500 text-xs italic">This submission does not have reply keys enabled. Thread messaging is not available.</p>
          {/if}
        </div>

        <!-- Priority & Assignment (responder+ only) -->
        {#if role === 'admin' || role === 'responder'}
          <div class="border-t border-slate-700 mt-4 pt-4">
            <h3 class="text-sm font-medium text-slate-300 mb-3">Priority & Assignment</h3>
            <div class="flex gap-4 items-end">
              <div>
                <label for="detail-priority" class="block text-xs text-slate-400 mb-1">Priority</label>
                <select id="detail-priority" value={submissionData.submission.priority || 'normal'}
                  onchange={(e) => updatePriorityLocal(e.target.value)}
                  class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-white text-sm">
                  <option value="low">Low</option>
                  <option value="normal">Normal</option>
                  <option value="high">High</option>
                  <option value="urgent">Urgent</option>
                </select>
              </div>
              <div>
                <label for="detail-assign" class="block text-xs text-slate-400 mb-1">Assigned to</label>
                <select id="detail-assign" value={submissionData.submission.assigned_to || ''}
                  onchange={(e) => assignSubmissionLocal(e.target.value || null)}
                  class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-white text-sm">
                  <option value="">Unassigned</option>
                  {#each teamMembers as m}
                    <option value={m.id}>{m.email}</option>
                  {/each}
                </select>
              </div>
            </div>
          </div>
        {/if}

        <!-- Internal Notes (threaded) -->
        <div class="border-t border-slate-700 mt-4 pt-4">
          <h3 class="text-sm font-medium text-slate-300 mb-3">Internal Notes</h3>

          {#if notes.length > 0}
            <div class="space-y-2 mb-4">
              {#each notes as note}
                <div class="bg-slate-700/50 rounded-lg p-3"
                  style="margin-left: {note.depth * 24}px; border-left: {note.depth > 0 ? '2px border-emerald-500' : 'none'}">
                  <div class="flex items-center gap-2 mb-1">
                    <span class="text-xs text-emerald-400 font-medium">{note.author_email}</span>
                    <span class="text-xs text-slate-500">({note.author_role})</span>
                    <span class="text-xs text-slate-500">· {new Date(note.created_at).toLocaleString()}</span>
                  </div>
                  <p class="text-white text-sm markdown-content">{@html renderMarkdown(note.content)}</p>
                  {#if (role === 'admin' || role === 'responder')}
                    <button onclick={() => { replyToNoteId = replyToNoteId === note.id ? null : note.id; }}
                      class="text-xs text-slate-400 hover:text-emerald-400 mt-1 cursor-pointer">
                      {replyToNoteId === note.id ? 'Cancel reply' : '↩ Reply'}
                    </button>
                  {/if}
                </div>
              {/each}
            </div>
          {:else}
            <p class="text-slate-500 text-xs mb-3">No notes yet.</p>
          {/if}

          {#if role === 'admin' || role === 'responder'}
            {#if replyToNoteId}
              <p class="text-xs text-slate-400 mb-1">↩ Replying to note</p>
            {/if}
            <div class="flex gap-2">
              <input type="text" bind:value={noteText} maxlength="10000"
                onkeydown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); addNote(); } }}
                class="flex-1 px-3 py-2 bg-slate-600 border border-slate-500 rounded-lg text-white text-sm placeholder-slate-400 focus:outline-none focus:border-emerald-500"
                placeholder={replyToNoteId ? 'Reply to note...' : 'Add a note...'} />
              <button onclick={addNote} disabled={sendingNote || !noteText.trim()}
                class="bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white text-sm px-4 py-2 rounded-lg transition cursor-pointer">
                {sendingNote ? '...' : 'Add'}
              </button>
            </div>
            {#if noteError}
              <p class="text-red-400 text-xs mt-1">{noteError}</p>
            {/if}
          {/if}
        </div>

        <!-- Activity Timeline -->
        <div class="border-t border-slate-700 mt-4 pt-4">
          <h3 class="text-sm font-medium text-slate-300 mb-3">Activity Log</h3>
          {#if activities.length > 0}
            <div class="space-y-2">
              {#each activities as act}
                <div class="flex items-start gap-3 text-xs">
                  <span class="text-slate-500 w-36 flex-shrink-0">{new Date(act.created_at).toLocaleString()}</span>
                  <span class="text-slate-400 w-20 flex-shrink-0">{act.action_type}</span>
                  <span class="text-white">{act.detail}</span>
                  <span class="text-slate-500">({act.actor_email})</span>
                </div>
              {/each}
            </div>
          {:else}
            <p class="text-slate-500 text-xs">No activity recorded.</p>
          {/if}
        </div>
      </div>
    {/if}
  </div>
</div>
