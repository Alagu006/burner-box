<script>
  import { decryptFromSender, encryptForRecipient, decryptFile, getStoredPrivateKey } from '$lib/crypto';
  import { API_URL } from '$lib/api';

  let token = $state('');
  let submissions = $state([]);
  let loading = $state(true);
  let error = $state('');
  let selectedSubmission = $state(null);
  let previewUrl = $state('');
  let previewFileName = $state('');
  let role = $state('reader');

  // Filters
  let filterStatus = $state('');
  let filterPriority = $state('');
  let filterAssignedToMe = $state(false);
  let sortBy = $state('created_at');
  let sortOrder = $state('desc');

  // Bulk selection
  let selectedIds = $state(new Set());
  let teamMembers = $state([]);

  $effect(() => {
    token = localStorage.getItem('burnerbox_token') || '';
    if (token) {
      loadSubmissions();
      loadTeamMembers();
      loadRole();
    } else {
      window.location.href = '/login';
    }
  });

  async function loadRole() {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (resp.ok) {
        const data = await resp.json();
        role = data.role || 'reader';
      }
    } catch { /* skip */ }
  }

  async function loadTeamMembers() {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/team/`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (resp.ok) {
        const data = await resp.json();
        teamMembers = data.members || [];
      }
    } catch { /* skip */ }
  }

  async function loadSubmissions() {
    loading = true;
    error = '';
    selectedIds = new Set();
    
    const params = new URLSearchParams();
    if (filterStatus) params.set('status', filterStatus);
    if (filterPriority) params.set('priority', filterPriority);
    if (filterAssignedToMe) params.set('assigned_to_me', 'true');
    params.set('sort', sortBy);
    params.set('order', sortOrder);

    try {
      const response = await fetch(`${API_URL}/api/v1/dashboard/submissions/?${params}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.status === 401) {
        localStorage.removeItem('burnerbox_token');
        localStorage.removeItem('burnerbox_org');
        window.location.href = '/login';
        return;
      }

      const data = await response.json();
      
      if (!response.ok) {
        error = data.error || 'Failed to load submissions';
      } else {
        submissions = data.submissions || [];
      }
    } catch (err) {
      error = 'Cannot connect to backend. Is it running?';
    }

    loading = false;
  }

  async function viewSubmission(id) {
    try {
      const response = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      const data = await response.json();
      
      if (response.ok) {
        selectedSubmission = data;
        
        // Decrypt message if encrypted
        if (selectedSubmission.submission.encrypted_message) {
          await decryptSubmissionMessage(selectedSubmission);
        }
      } else {
        error = data.error || 'Failed to load submission';
      }
    } catch (err) {
      error = 'Network error';
    }
  }

  async function decryptSubmissionMessage(submissionData) {
    try {
      const privateKey = await getStoredPrivateKey();
      
      if (!privateKey) {
        submissionData.submission.decrypted_message = '🔒 Private key not found. Please login again or regenerate your key.';
        return;
      }

      const meta = JSON.parse(submissionData.submission.encryption_meta);
      
      const decryptedText = await decryptFromSender(
        {
          ciphertext: submissionData.submission.encrypted_message,
          nonce: meta.nonce,
          encryptedKey: meta.encryptedKey,
          boxNonce: meta.boxNonce,
          senderPublicKey: meta.senderPublicKey,
        },
        privateKey
      );
      
      submissionData.submission.decrypted_message = decryptedText;
      
    } catch {
      submissionData.submission.decrypted_message = '❌ Decryption failed. The message cannot be read.';
    }
  }

  async function updateStatus(id, newStatus) {
    try {
      const response = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: newStatus }),
      });

      const data = await response.json();
      
      if (response.ok) {
        loadSubmissions();
        if (selectedSubmission?.submission?.id === id) {
          selectedSubmission.submission.status = newStatus;
        }
      } else {
        error = data.error || 'Failed to update status';
      }
    } catch (err) {
      error = 'Network error';
    }
  }

  async function uploadFile(submissionId, fileInput) {
    const file = fileInput.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(
        `${API_URL}/api/v1/dashboard/submissions/${submissionId}/files`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
          body: formData,
        }
      );

      const data = await response.json();
      
      if (response.ok) {
        alert('File uploaded: ' + data.file.file_name);
        if (selectedSubmission) {
          viewSubmission(submissionId);
        }
      } else {
        alert('Upload failed: ' + (data.error || 'Unknown error'));
      }
    } catch (err) {
      alert('Network error during upload');
    }
  }

  async function addNote(submissionId, noteText) {
    if (!noteText.trim()) return;

    try {
      const response = await fetch(
        `${API_URL}/api/v1/dashboard/submissions/${submissionId}/notes`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ note: noteText }),
        }
      );

      const data = await response.json();
      
      if (response.ok) {
        if (selectedSubmission) {
          viewSubmission(submissionId);
        }
      } else {
        alert('Failed to add note: ' + (data.error || 'Unknown error'));
      }
    } catch (err) {
      alert('Network error');
    }
  }

  async function replyToSubmission(submissionId, replyText) {
    if (!replyText.trim()) return;

    try {
      let body;
      const submission = selectedSubmission?.submission;

      // If submission has a reply key, encrypt the reply with it
      if (submission?.reply_public_key) {
        const encResult = await encryptForRecipient(replyText, submission.reply_public_key);
        body = JSON.stringify({
          encrypted_message: encResult.ciphertext,
          encryption_meta: JSON.stringify({
            nonce: encResult.nonce,
            encryptedKey: encResult.encryptedKey,
            boxNonce: encResult.boxNonce,
            senderPublicKey: encResult.senderPublicKey,
          }),
        });
      } else {
        body = JSON.stringify({ message_text: replyText });
      }

      const response = await fetch(
        `${API_URL}/api/v1/dashboard/submissions/${submissionId}/reply`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body,
        }
      );

      const data = await response.json();
      
      if (response.ok) {
        alert('Reply sent!');
        if (selectedSubmission) {
          viewSubmission(submissionId);
        }
      } else {
        alert('Failed to reply: ' + (data.error || 'Unknown error'));
      }
    } catch (err) {
      alert('Network error');
    }
  }

  function fileIcon(mimeType) {
    if (!mimeType) return '📄';
    if (mimeType.startsWith('image/')) return '🖼️';
    if (mimeType.startsWith('video/')) return '🎬';
    if (mimeType.startsWith('audio/')) return '🎵';
    if (mimeType === 'application/pdf') return '📕';
    if (mimeType.includes('zip')) return '🗜️';
    if (mimeType.includes('text/')) return '📝';
    return '📄';
  }

  async function downloadFile(submissionId, file) {
    try {
      const response = await fetch(
        `${API_URL}/api/v1/dashboard/submissions/${submissionId}/files/${file.id}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        alert('Download failed: ' + (data.error || 'Unknown error'));
        return;
      }

      let blob;
      const clientMeta = response.headers.get('X-Client-Encryption-Meta');
      if (clientMeta) {
        try {
          const privateKey = await getStoredPrivateKey();
          if (!privateKey) {
            alert('Cannot decrypt file: private key not found. Please login with your password.');
            return;
          }
          const ciphertext = await response.arrayBuffer();
          const metaMap = JSON.parse(clientMeta);
          const fileMeta = metaMap[file.file_name];
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
          const raw = await response.blob();
          blob = raw;
        }
      } else {
        blob = await response.blob();
      }

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.file_name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

    } catch (err) {
      alert('Network error during download');
    }
  }

  async function previewFile(submissionId, file) {
    try {
      const response = await fetch(
        `${API_URL}/api/v1/dashboard/submissions/${submissionId}/files/${file.id}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        alert('Preview failed');
        return;
      }

      let blob;
      const clientMeta = response.headers.get('X-Client-Encryption-Meta');
      if (clientMeta) {
        try {
          const privateKey = await getStoredPrivateKey();
          if (!privateKey) {
            alert('Cannot decrypt file for preview: private key not available. Please login with your password.');
            return;
          }
          const ciphertext = await response.arrayBuffer();
          const metaMap = JSON.parse(clientMeta);
          const fileMeta = metaMap[file.file_name];
          if (fileMeta) {
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
            blob = new Blob([decrypted], { type: file.mime_type });
          } else {
            blob = new Blob([ciphertext], { type: file.mime_type });
          }
        } catch {
          blob = await response.blob();
        }
      } else {
        blob = await response.blob();
      }

      previewUrl = window.URL.createObjectURL(blob);
      previewFileName = file.file_name;

    } catch (err) {
      alert('Network error during preview');
    }
  }

  function closePreview() {
    if (previewUrl) {
      window.URL.revokeObjectURL(previewUrl);
    }
    previewUrl = '';
    previewFileName = '';
  }

  function closeDetail() {
    selectedSubmission = null;
    closePreview();
  }

  // Bulk selection
  function toggleSelect(id) {
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    selectedIds = next;
  }

  function toggleSelectAll() {
    if (selectedIds.size === submissions.length) {
      selectedIds = new Set();
    } else {
      selectedIds = new Set(submissions.map(s => s.id));
    }
  }

  async function bulkUpdateStatus(status) {
    if (selectedIds.size === 0) return;
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/bulk/status`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: [...selectedIds], status }),
      });
      if (resp.ok) {
        selectedIds = new Set();
        loadSubmissions();
      } else {
        const data = await resp.json();
        error = data.error || 'Bulk update failed';
      }
    } catch { error = 'Network error'; }
  }

  async function bulkAssign(memberId) {
    if (selectedIds.size === 0) return;
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/bulk/assign`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: [...selectedIds], assigned_to: memberId || null }),
      });
      if (resp.ok) {
        selectedIds = new Set();
        loadSubmissions();
      }
    } catch { /* skip */ }
  }

  async function updatePriority(id, priority) {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ priority }),
      });
      if (resp.ok) loadSubmissions();
    } catch { /* skip */ }
  }

  async function assignSubmission(id, memberId) {
    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/${id}/assign`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ assigned_to: memberId || null }),
      });
      if (resp.ok) {
        loadSubmissions();
        if (selectedSubmission?.submission?.id === id) viewSubmission(id);
      }
    } catch { /* skip */ }
  }

  function priorityColor(p) {
    const colors = { low: 'bg-slate-600', normal: 'bg-blue-600', high: 'bg-orange-600', urgent: 'bg-red-600' };
    return colors[p] || 'bg-slate-600';
  }

  function statusColor(s) {
    const colors = { unread: 'bg-yellow-600', read: 'bg-blue-600', actioned: 'bg-emerald-600', flagged: 'bg-red-600', archived: 'bg-slate-500' };
    return colors[s] || 'bg-slate-600';
  }

  function formatDate(dateString) {
    if (!dateString) return '';
    return new Date(dateString).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  // Export
  async function exportSelected() {
    const ids = selectedIds.size > 0 ? [...selectedIds] : submissions.map(s => s.id);
    if (ids.length === 0) { error = 'No submissions to export'; return; }

    const password = prompt('Set a password for the encrypted zip file:');
    if (!password) return;

    try {
      const resp = await fetch(`${API_URL}/api/v1/dashboard/submissions/export`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      });
      if (!resp.ok) { error = 'Export failed'; return; }
      const data = await resp.json();
      await buildExportZip(data.data_json, data.count, password);
    } catch { error = 'Export network error'; }
  }

  async function buildExportZip(encodedJson, count, password) {
    const { default: JSZip } = await import('jszip');
    const zip = new JSZip();
    const submissionsData = JSON.parse(atob(encodedJson));

    for (const sub of submissionsData) {
      const folder = zip.folder(sub.id + '_' + sub.anonymous_name.replace(/[^a-zA-Z0-9]/g, '_'));
      folder.file('message.json', JSON.stringify({
        id: sub.id, anonymous_name: sub.anonymous_name, status: sub.status,
        priority: sub.priority, created_at: sub.created_at, updated_at: sub.updated_at,
        encrypted_message: sub.encrypted_message, encryption_meta: sub.encryption_meta,
        message_text: sub.message_text,
      }, null, 2));
      if (sub.replies?.length) folder.file('replies.json', JSON.stringify(sub.replies, null, 2));
      if (sub.notes?.length) folder.file('notes.json', JSON.stringify(sub.notes, null, 2));
      if (sub.thread?.length) folder.file('thread.json', JSON.stringify(sub.thread, null, 2));
      if (sub.files?.length) folder.file('files-metadata.json', JSON.stringify(sub.files, null, 2));
    }

    zip.file('export-info.json', JSON.stringify({
      exported_at: new Date().toISOString(), submission_count: count,
      note: 'Encrypted messages require the org private key to decrypt.',
    }, null, 2));

    const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `burnerbox-export-${new Date().toISOString().slice(0,10)}.zip`;
    a.click(); URL.revokeObjectURL(url);
  }
</script>

<div class="min-h-screen bg-slate-900 p-4">
  <div class="max-w-6xl mx-auto">
    
    <!-- Header -->
    <div class="flex justify-between items-center mb-6">
      <div>
        <a href="/dashboard" class="text-slate-400 hover:text-white text-sm mb-2 inline-block">
          ← Back to Dashboard
        </a>
        <h1 class="text-2xl font-bold text-white">📨 Submissions</h1>
      </div>
      <button
        onclick={loadSubmissions}
        class="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm transition cursor-pointer"
      >
        🔄 Refresh
      </button>
    </div>

    {#if error}
      <div class="bg-red-900/50 border border-red-500 rounded-lg p-4 mb-4">
        <p class="text-red-400">{error}</p>
      </div>
    {/if}

    <!-- Filters -->
    <div class="bg-slate-800 rounded-lg p-4 mb-4 shadow-xl flex flex-wrap gap-3 items-end">
      <div>
        <label for="f-status" class="block text-xs text-slate-400 mb-1">Status</label>
        <select id="f-status" bind:value={filterStatus} onchange={loadSubmissions}
          class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-white text-sm">
          <option value="">All</option>
          <option value="unread">Unread</option>
          <option value="read">Read</option>
          <option value="actioned">Actioned</option>
          <option value="flagged">Flagged</option>
          <option value="archived">Archived</option>
        </select>
      </div>
      <div>
        <label for="f-priority" class="block text-xs text-slate-400 mb-1">Priority</label>
        <select id="f-priority" bind:value={filterPriority} onchange={loadSubmissions}
          class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-white text-sm">
          <option value="">All</option>
          <option value="low">Low</option>
          <option value="normal">Normal</option>
          <option value="high">High</option>
          <option value="urgent">Urgent</option>
        </select>
      </div>
      <div>
        <label for="f-sort" class="block text-xs text-slate-400 mb-1">Sort by</label>
        <select id="f-sort" bind:value={sortBy} onchange={loadSubmissions}
          class="bg-slate-700 border border-slate-600 rounded px-3 py-1.5 text-white text-sm">
          <option value="created_at">Date</option>
          <option value="priority">Priority</option>
          <option value="status">Status</option>
          <option value="updated_at">Updated</option>
        </select>
      </div>
      <div>
        <button onclick={() => { sortOrder = sortOrder === 'desc' ? 'asc' : 'desc'; loadSubmissions(); }}
          class="bg-slate-700 hover:bg-slate-600 text-white px-3 py-1.5 rounded text-sm cursor-pointer">
          {sortOrder === 'desc' ? '↓ Desc' : '↑ Asc'}
        </button>
      </div>
      <label class="flex items-center gap-2 cursor-pointer">
        <input type="checkbox" checked={filterAssignedToMe} onchange={(e) => { filterAssignedToMe = e.target.checked; loadSubmissions(); }}
          class="rounded bg-slate-700 border-slate-600 text-emerald-500" />
        <span class="text-sm text-slate-300">Assigned to me</span>
      </label>
    </div>

    <!-- Bulk Actions Bar -->
    {#if selectedIds.size > 0}
      <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-3 mb-4 flex flex-wrap gap-3 items-center">
        <span class="text-emerald-400 text-sm font-medium">{selectedIds.size} selected</span>
        <button onclick={() => bulkUpdateStatus('read')} class="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1 rounded text-xs cursor-pointer">✓ Mark Read</button>
        <button onclick={() => bulkUpdateStatus('actioned')} class="bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1 rounded text-xs cursor-pointer">✅ Actioned</button>
        <button onclick={() => bulkUpdateStatus('archived')} class="bg-slate-600 hover:bg-slate-500 text-white px-3 py-1 rounded text-xs cursor-pointer">📦 Archive</button>
        {#if role === 'admin' || role === 'responder'}
          <select onchange={(e) => { if (e.target.value) bulkAssign(e.target.value); e.target.value = ''; }}
            class="bg-slate-700 border border-slate-600 rounded px-2 py-1 text-white text-xs">
            <option value="">Assign to...</option>
            {#each teamMembers as m}
              <option value={m.id}>{m.email} ({m.role})</option>
            {/each}
          </select>
        {/if}
        <button onclick={exportSelected} class="bg-purple-600 hover:bg-purple-500 text-white px-3 py-1 rounded text-xs cursor-pointer">📦 Export</button>
        <button onclick={() => selectedIds = new Set()} class="text-slate-400 hover:text-white text-xs cursor-pointer">Clear</button>
      </div>
    {/if}

    {#if loading}
      <div class="bg-slate-800 rounded-lg p-12 text-center shadow-xl">
        <p class="text-slate-400 text-lg">⏳ Loading submissions...</p>
      </div>
      
    {:else if submissions.length === 0}
      <div class="bg-slate-800 rounded-lg p-12 text-center shadow-xl">
        <p class="text-slate-400 text-lg mb-2">📭 No submissions yet</p>
        <p class="text-slate-500 text-sm">
          Share your submission portal URL to start receiving anonymous tips.
        </p>
      </div>
      
    {:else}
      <!-- Submissions Table -->
      <div class="bg-slate-800 rounded-lg shadow-xl overflow-hidden">
        
        <!-- Table Header -->
        <div class="grid grid-cols-13 gap-3 p-4 bg-slate-700 text-sm font-medium text-slate-300">
          <div class="col-span-1">
            <input type="checkbox" checked={selectedIds.size === submissions.length && submissions.length > 0}
              onchange={toggleSelectAll}
              class="rounded bg-slate-700 border-slate-600 text-emerald-500 cursor-pointer" />
          </div>
          <div class="col-span-2">Anonymous Name</div>
          <div class="col-span-1">Priority</div>
          <div class="col-span-3">Message Preview</div>
          <div class="col-span-1">Status</div>
          <div class="col-span-2">Assigned</div>
          <div class="col-span-1">Date</div>
          <div class="col-span-2">Actions</div>
        </div>

        <!-- Table Rows -->
        {#each submissions as submission}
          <div class="grid grid-cols-13 gap-3 p-4 border-b border-slate-700 hover:bg-slate-750 text-sm items-center">
            
            <!-- Checkbox -->
            <div class="col-span-1">
              <input type="checkbox" checked={selectedIds.has(submission.id)}
                onchange={() => toggleSelect(submission.id)}
                class="rounded bg-slate-700 border-slate-600 text-emerald-500 cursor-pointer" />
            </div>

            <!-- Anonymous Name -->
            <div class="col-span-2">
              <span class="text-white font-medium">{submission.anonymous_name}</span>
              {#if submission.has_files}
                <span class="text-slate-500 text-xs ml-1">📎</span>
              {/if}
              {#if submission.encrypted_message}
                <span class="text-emerald-500 text-xs ml-1">🔒</span>
              {/if}
            </div>

            <!-- Priority -->
            <div class="col-span-1">
              {#if role === 'admin' || role === 'responder'}
                <select value={submission.priority || 'normal'}
                  onchange={(e) => updatePriority(submission.id, e.target.value)}
                  class="text-xs px-1 py-0.5 rounded {priorityColor(submission.priority || 'normal')} text-white border-none cursor-pointer bg-opacity-100">
                  <option value="low">low</option>
                  <option value="normal">normal</option>
                  <option value="high">high</option>
                  <option value="urgent">urgent</option>
                </select>
              {:else}
                <span class="text-xs text-white px-2 py-0.5 rounded {priorityColor(submission.priority || 'normal')}">
                  {submission.priority || 'normal'}
                </span>
              {/if}
            </div>

            <!-- Message Preview -->
            <div class="col-span-3">
              {#if submission.encrypted_message}
                <p class="text-slate-500 italic text-xs">🔒 Encrypted message</p>
              {:else}
                <p class="text-slate-400 truncate">
                  {submission.message_text?.substring(0, 80) || '(No message)'}
                </p>
              {/if}
            </div>

            <!-- Status -->
            <div class="col-span-1">
              <span class="text-xs text-white px-2 py-1 rounded-full {statusColor(submission.status)}">
                {submission.status}
              </span>
            </div>

            <!-- Assigned -->
            <div class="col-span-2 text-xs text-slate-400">
              {#if submission.assignee}
                {submission.assignee.email}
              {:else}
                —
              {/if}
            </div>

            <!-- Date -->
            <div class="col-span-1 text-slate-400 text-xs">
              {formatDate(submission.created_at)}
            </div>

            <!-- Actions -->
            <div class="col-span-2 flex gap-1">
              <button
                onclick={() => viewSubmission(submission.id)}
                class="bg-slate-600 hover:bg-slate-500 text-white px-2 py-1 rounded text-xs transition cursor-pointer"
              >
                👁
              </button>
              
              {#if submission.status === 'unread'}
                <button
                  onclick={() => updateStatus(submission.id, 'read')}
                  class="bg-yellow-600 hover:bg-yellow-500 text-white px-2 py-1 rounded text-xs transition cursor-pointer"
                >
                  ✓
                </button>
              {/if}
            </div>
          </div>
        {/each}
      </div>

      <!-- Count -->
      <p class="text-slate-500 text-sm mt-4">
        Total: {submissions.length} submission(s)
      </p>
    {/if}

    <!-- Submission Detail Modal -->
    {#if selectedSubmission && selectedSubmission.submission}
      <!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
      <div class="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50" onclick={closeDetail} onkeydown={(e) => { if (e.key === 'Escape') closeDetail(); }}>
        <div 
          class="bg-slate-800 rounded-lg p-6 max-w-2xl w-full max-h-[80vh] overflow-y-auto shadow-2xl"
          onclick={(e) => e.stopPropagation()}
          onkeydown={(e) => e.stopPropagation()}
          role="dialog"
          aria-modal="true"
          aria-label="Submission detail"
          tabindex="-1"
        >
          
          <!-- Modal Header -->
          <div class="flex justify-between items-start mb-4">
            <div>
              <h2 class="text-xl font-bold text-white">
                {selectedSubmission.submission.anonymous_name}
              </h2>
              <div class="flex gap-2 mt-1">
                <span class="text-xs text-white px-2 py-0.5 rounded-full {statusColor(selectedSubmission.submission.status)}">
                  {selectedSubmission.submission.status}
                </span>
                {#if selectedSubmission.submission.encrypted_message}
                  <span class="text-xs text-emerald-400 px-2 py-0.5 rounded-full bg-emerald-900/50">
                    🔒 E2E Encrypted
                  </span>
                {/if}
              </div>
            </div>
            <button
              onclick={closeDetail}
              class="text-slate-400 hover:text-white text-2xl transition cursor-pointer"
            >
              ✕
            </button>
          </div>

          <!-- Message -->
          <div class="bg-slate-700 rounded-lg p-4 mb-4">
            {#if selectedSubmission.submission.decrypted_message}
              <p class="text-white whitespace-pre-wrap">{selectedSubmission.submission.decrypted_message}</p>
            {:else if selectedSubmission.submission.message_text}
              <p class="text-white whitespace-pre-wrap">{selectedSubmission.submission.message_text}</p>
            {:else if selectedSubmission.submission.encrypted_message}
              <p class="text-slate-500 italic">🔒 Encrypted message (decrypting...)</p>
            {:else}
              <p class="text-slate-500 italic">(No message)</p>
            {/if}
          </div>

          <!-- Meta Info -->
          <div class="text-slate-400 text-xs mb-4 space-y-1">
            <p>📅 Received: {formatDate(selectedSubmission.submission.created_at)}</p>
            <p>🔑 Reply Key: {selectedSubmission.submission.has_reply_key ? 'Provided ✅' : 'Not provided ❌'}</p>
            <p>📎 Files: {selectedSubmission.files?.length || 0}</p>
            <p>🔐 Encryption: {selectedSubmission.submission.encrypted_message ? 'End-to-End Encrypted' : 'Plaintext (Legacy)'}</p>
          </div>

          <!-- Files (if any) -->
          {#if selectedSubmission.files?.length > 0}
            <div class="mb-4">
              <h3 class="text-sm font-medium text-slate-300 mb-2">
                📎 Attached Files ({selectedSubmission.files.length})
              </h3>
              <div class="space-y-2">
                {#each selectedSubmission.files as file}
                  <div class="bg-slate-700 rounded-lg p-3 flex items-center justify-between">
                    <div class="flex items-center gap-3">
                      <span class="text-2xl">{fileIcon(file.mime_type)}</span>
                      <div>
                        <p class="text-white text-sm font-medium">{file.file_name}</p>
                        <p class="text-slate-400 text-xs">
                          {(file.file_size / 1024).toFixed(1)} KB • {file.mime_type || 'Unknown type'}
                        </p>
                      </div>
                    </div>
                    <div class="flex gap-2">
                      {#if file.mime_type?.startsWith('image/')}
                        <button
                          onclick={() => previewFile(selectedSubmission.submission.id, file)}
                          class="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded text-xs transition cursor-pointer"
                        >
                          👁 Preview
                        </button>
                      {/if}
                      <button
                        onclick={() => downloadFile(selectedSubmission.submission.id, file)}
                        class="bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1.5 rounded text-xs transition cursor-pointer"
                      >
                        ⬇ Download
                      </button>
                    </div>
                  </div>
                {/each}
              </div>
            </div>
          {/if}

          <!-- Replies (if any) -->
          {#if selectedSubmission.replies?.length > 0}
            <div class="mb-4">
              <h3 class="text-sm font-medium text-slate-300 mb-2">Replies:</h3>
              {#each selectedSubmission.replies as reply}
                <div class="bg-slate-700 rounded p-3 mb-2">
                  {#if reply.encrypted_message}
                    <p class="text-slate-400 italic text-sm">🔒 Encrypted reply (only the submitter can decrypt)</p>
                  {:else}
                    <p class="text-slate-300 text-sm">{reply.message_text}</p>
                  {/if}
                  <p class="text-slate-500 text-xs mt-1">{formatDate(reply.created_at)}</p>
                </div>
              {/each}
            </div>
          {/if}

          <!-- Action Buttons -->
          <div class="flex gap-2 flex-wrap mb-4">
            <button
              onclick={() => updateStatus(selectedSubmission.submission.id, 'actioned')}
              class="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded text-sm transition cursor-pointer"
            >
              ✅ Mark Actioned
            </button>
            <button
              onclick={() => updateStatus(selectedSubmission.submission.id, 'flagged')}
              class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded text-sm transition cursor-pointer"
            >
              🚩 Flag
            </button>
          </div>

          <!-- File Upload -->
          <div class="mt-4 p-4 bg-slate-700 rounded-lg">
            <h3 class="text-sm font-medium text-slate-300 mb-2">📎 Attach File</h3>
            <input
              type="file"
              onchange={(e) => {
                if (e.target.files[0]) {
                  uploadFile(selectedSubmission.submission.id, e.target);
                }
              }}
              class="text-slate-400 text-sm"
            />
            <p class="text-slate-500 text-xs mt-1">
              Max size: 10MB. Metadata is stripped before upload.
            </p>
          </div>

          <!-- Internal Notes -->
          <div class="mt-4 p-4 bg-slate-700 rounded-lg">
            <h3 class="text-sm font-medium text-slate-300 mb-2">📝 Internal Notes</h3>
            <textarea
              id="internalNote"
              rows="2"
              class="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded-lg text-white text-sm focus:outline-none focus:border-emerald-500"
              placeholder="Add a private note for your team..."
            ></textarea>
            <button
              onclick={() => {
                const noteText = document.getElementById('internalNote').value;
                addNote(selectedSubmission.submission.id, noteText);
                document.getElementById('internalNote').value = '';
              }}
              class="mt-2 bg-slate-600 hover:bg-slate-500 text-white px-3 py-1 rounded text-xs transition cursor-pointer"
            >
              Add Note
            </button>
            {#if selectedSubmission.submission.internal_notes}
              <div class="mt-3 text-xs text-slate-400 whitespace-pre-wrap bg-slate-600 p-2 rounded">
                {selectedSubmission.submission.internal_notes}
              </div>
            {/if}
          </div>

          <!-- Reply -->
          <div class="mt-4 p-4 bg-slate-700 rounded-lg">
            <h3 class="text-sm font-medium text-slate-300 mb-2">💬 Reply to Submitter</h3>
            {#if selectedSubmission.submission.has_reply_key}
              <textarea
                id="replyText"
                rows="2"
                class="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded-lg text-white text-sm focus:outline-none focus:border-emerald-500"
                placeholder="Type your reply..."
              ></textarea>
              <button
                onclick={() => {
                  const replyText = document.getElementById('replyText').value;
                  replyToSubmission(selectedSubmission.submission.id, replyText);
                  document.getElementById('replyText').value = '';
                }}
                class="mt-2 bg-emerald-600 hover:bg-emerald-700 text-white px-3 py-1 rounded text-xs transition cursor-pointer"
              >
                Send Reply
              </button>
            {:else}
              <p class="text-slate-500 text-xs">
                Submitter did not enable replies for this submission.
              </p>
            {/if}
          </div>

        </div>
      </div>
    {/if}

    <!-- Image Preview Modal -->
    {#if previewUrl}
      <!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
      <div class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-[60]" onclick={closePreview} onkeydown={(e) => { if (e.key === 'Escape') closePreview(); }}>
        <div 
          class="bg-slate-800 rounded-lg p-4 max-w-3xl w-full"
          onclick={(e) => e.stopPropagation()}
          onkeydown={(e) => e.stopPropagation()}
          role="dialog"
          aria-modal="true"
          aria-label="File preview"
          tabindex="-1"
        >
          <div class="flex justify-between items-center mb-3">
            <h3 class="text-white font-medium text-sm truncate">{previewFileName}</h3>
            <button
              onclick={closePreview}
              class="text-slate-400 hover:text-white text-xl transition cursor-pointer"
            >
              ✕
            </button>
          </div>
          <img 
            src={previewUrl} 
            alt={previewFileName}
            class="max-w-full max-h-[70vh] mx-auto rounded-lg"
          />
          <div class="mt-3 text-center">
            <a
              href={previewUrl}
              download={previewFileName}
              class="text-emerald-400 hover:text-emerald-300 text-sm"
            >
              ⬇ Download this file
            </a>
          </div>
        </div>
      </div>
    {/if}
  </div>
</div>