<script>
  import { decryptFromSender, encryptForRecipient } from '$lib/crypto';
  import { API_URL, WS_URL } from '$lib/api';

  let anonymousName = $state('');
  let timeline = $state([]);
  let loading = $state(false);
  let error = $state('');
  let success = $state(false);
  let submissionId = $state('');
  let submissionStatus = $state('');
  let decrypting = $state(false);
  let decryptionErrors = $state({});

  // Thread follow-up
  let followUpText = $state('');
  let sendingFollowUp = $state(false);
  let followUpError = $state('');
  let followUpSuccess = $state(false);
  let orgPublicKey = $state('');

  // Status notification state
  let statusWs = $state(null);
  let statusConnected = $state(false);
  let pollingTimer = $state(null);
  let slug = $state('');
  let lastPollTime = $state('');

  async function checkReplies(e) {
    e.preventDefault();
    error = '';
    loading = true;
    success = false;
    timeline = [];
    decryptionErrors = {};

    if (!anonymousName.trim()) {
      error = 'Please enter your anonymous name';
      loading = false;
      return;
    }

    try {
      // Fetch thread timeline (includes legacy replies + new thread messages)
      const response = await fetch(
        `${API_URL}/api/v1/thread/?name=${encodeURIComponent(anonymousName)}&submission_id=`
      );

      // CheckForReplies returns submission_id — use it for thread endpoint
      const basicResp = await fetch(
        `${API_URL}/api/v1/submit/replies?name=${encodeURIComponent(anonymousName)}`
      );
      const basicData = await basicResp.json();

      if (!basicResp.ok) {
        error = basicData.error || 'Failed to check replies';
        loading = false;
        return;
      }

      submissionId = basicData.submission_id;
      submissionStatus = basicData.status || '';
      slug = basicData.slug || '';
      orgPublicKey = basicData.reply_key || '';

      // Now fetch the full thread
      const threadResp = await fetch(
        `${API_URL}/api/v1/thread/?name=${encodeURIComponent(anonymousName)}&submission_id=${encodeURIComponent(submissionId)}`
      );
      const threadData = await threadResp.json();

      if (threadResp.ok) {
        timeline = threadData.timeline || [];
        await decryptTimeline(timeline);
      } else {
        // Fall back to replies-only format
        timeline = (basicData.replies || []).map(r => ({
          id: r.id,
          sender_type: 'org',
          encrypted_text: r.encrypted_message,
          encryption_meta: r.encryption_meta,
          message_text: r.message_text,
          created_at: r.created_at,
          source: 'reply',
        }));
        await decryptTimeline(timeline);
      }

      success = true;
      connectStatusWs();

    } catch (err) {
      error = 'Network error. Cannot reach server.';
    }

    loading = false;
  }

  async function decryptTimeline(entries) {
    const privateKey = localStorage.getItem('burnerbox_reply_private_key');
    if (!privateKey) {
      entries.forEach((entry, i) => {
        if (entry.encrypted_text) {
          decryptionErrors[i] = 'No decryption key in this browser. Use the same browser where you submitted.';
        }
      });
      return;
    }

    decrypting = true;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
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
        decryptionErrors[i] = 'Decryption failed — wrong key or corrupted data.';
      }
    }

    decrypting = false;
  }

  async function sendFollowUp() {
    followUpError = '';
    followUpSuccess = false;

    if (!followUpText.trim()) {
      followUpError = 'Please enter a message';
      return;
    }

    if (!orgPublicKey) {
      followUpError = 'No organization public key available for encryption';
      return;
    }

    sendingFollowUp = true;

    try {
      const encrypted = await encryptForRecipient(followUpText.trim(), orgPublicKey);

      const resp = await fetch(`${API_URL}/api/v1/thread/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          anonymous_name: anonymousName,
          submission_id: submissionId,
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
        followUpError = data.error || 'Failed to send message';
        sendingFollowUp = false;
        return;
      }

      // Add to local timeline
      const newEntry = {
        id: data.msg_id,
        sender_type: 'submitter',
        encrypted_text: encrypted.ciphertext,
        encryption_meta: JSON.stringify({
          nonce: encrypted.nonce,
          encryptedKey: encrypted.encryptedKey,
          boxNonce: encrypted.boxNonce,
          senderPublicKey: encrypted.senderPublicKey,
        }),
        message_text: '',
        created_at: new Date().toISOString(),
        source: 'thread',
        _decryptedText: followUpText.trim(),
      };
      timeline = [...timeline, newEntry];
      followUpText = '';
      followUpSuccess = true;
      setTimeout(() => { followUpSuccess = false; }, 3000);

    } catch {
      followUpError = 'Network error. Cannot reach server.';
    }

    sendingFollowUp = false;
  }

  function connectStatusWs() {
    disconnectStatusWs();
    if (!slug || !anonymousName) return;

    const wsUrl = `${WS_URL}/api/v1/submit/${encodeURIComponent(slug)}/status/${encodeURIComponent(anonymousName)}/ws`;

    try {
      const ws = new WebSocket(wsUrl);
      statusWs = ws;

      ws.onopen = () => {
        statusConnected = true;
        stopPolling();
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'status') {
            submissionStatus = msg.status;
          }
        } catch { /* ignore malformed */ }
      };

      ws.onerror = () => { statusConnected = false; };

      ws.onclose = () => {
        statusConnected = false;
        statusWs = null;
        startPolling();
      };

    } catch {
      startPolling();
    }
  }

  function disconnectStatusWs() {
    if (statusWs) { statusWs.close(); statusWs = null; }
    statusConnected = false;
    stopPolling();
  }

  function startPolling() {
    stopPolling();
    pollingTimer = setInterval(async () => {
      if (!anonymousName || !success) return;
      try {
        const resp = await fetch(
          `${API_URL}/api/v1/submit/replies?name=${encodeURIComponent(anonymousName)}`
        );
        if (resp.ok) {
          const data = await resp.json();
          if (data.status) submissionStatus = data.status;
          lastPollTime = new Date().toLocaleTimeString();
          // Reload thread for new messages
          if (data.submission_id) {
            const threadResp = await fetch(
              `${API_URL}/api/v1/thread/?name=${encodeURIComponent(anonymousName)}&submission_id=${encodeURIComponent(data.submission_id)}`
            );
            if (threadResp.ok) {
              const td = await threadResp.json();
              if (td.timeline && td.timeline.length > timeline.length) {
                const newEntries = td.timeline.slice(timeline.length);
                await decryptTimeline(newEntries);
                timeline = [...timeline, ...newEntries];
              }
            }
          }
        }
      } catch { /* skip */ }
    }, 30000);
  }

  function stopPolling() {
    if (pollingTimer) { clearInterval(pollingTimer); pollingTimer = null; }
  }

  function formatDate(dateString) {
    if (!dateString) return '';
    return new Date(dateString).toLocaleString('en-IN', {
      day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  }

  function statusLabel(s) {
    const labels = { unread: '📨 Unread', read: '👁️ Read', actioned: '✅ Actioned', flagged: '🚩 Flagged' };
    return labels[s] || s || 'Unknown';
  }

  function cleanup() {
    disconnectStatusWs();
  }

  $effect(() => {
    return () => cleanup();
  });
</script>

<div class="min-h-screen bg-slate-900 p-4">
  <div class="max-w-2xl mx-auto pt-8">
    
    <!-- Quick Exit -->
    <div class="fixed top-4 right-4 z-50">
      <button
        onclick={() => window.location.replace('https://www.weather.com')}
        class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-bold text-sm transition cursor-pointer shadow-lg"
      >
        ⚡ QUICK EXIT
      </button>
    </div>

    <div class="bg-slate-800 rounded-lg p-8 shadow-xl">
      <div class="text-center mb-6">
        <h1 class="text-2xl font-bold text-white">📬 Check for Replies</h1>
        <p class="text-slate-400 text-sm mt-2">
          Enter your anonymous identity to see replies and continue the conversation
        </p>
      </div>

      {#if error}
        <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
          <p class="text-red-400 text-sm">{error}</p>
        </div>
      {/if}

      {#if success}
        <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-4 mb-4">
          <p class="text-emerald-400 font-medium">✅ Found your submission!</p>
        </div>

        <div class="flex items-center gap-2 mb-4 text-sm">
          <span class="text-slate-400">Status:</span>
          <span class="text-white font-medium">{statusLabel(submissionStatus)}</span>
          {#if statusConnected}
            <span class="text-emerald-400 text-xs">● Live</span>
          {:else}
            <span class="text-slate-500 text-xs">● Polling{lastPollTime ? ` (${lastPollTime})` : ''}</span>
          {/if}
        </div>

        <!-- Thread Timeline -->
        <div class="space-y-3 mb-6">
          {#each timeline as entry, i}
            <div class="rounded-lg p-4 {entry.sender_type === 'org' ? 'bg-slate-700 border-l-2 border-emerald-500' : 'bg-slate-700/60 border-l-2 border-blue-400'}">
              <div class="flex items-center gap-2 mb-1">
                <span class="text-xs font-medium {entry.sender_type === 'org' ? 'text-emerald-400' : 'text-blue-300'}">
                  {entry.sender_type === 'org' ? '🏛️ Organization' : '👤 You'}
                </span>
                <span class="text-slate-500 text-xs">·</span>
                <span class="text-slate-500 text-xs">{formatDate(entry.created_at)}</span>
              </div>
              {#if entry._decryptedText}
                <p class="text-white text-sm whitespace-pre-wrap">{entry._decryptedText}</p>
              {:else if entry.encrypted_text}
                {#if decryptionErrors[i]}
                  <p class="text-red-400 text-sm">🔒 {decryptionErrors[i]}</p>
                {:else if decrypting}
                  <p class="text-slate-500 italic text-sm">🔐 Decrypting...</p>
                {:else}
                  <p class="text-slate-500 italic text-sm">🔒 Encrypted message</p>
                {/if}
              {:else if entry.message_text}
                <p class="text-white text-sm whitespace-pre-wrap">{entry.message_text}</p>
              {/if}
            </div>
          {/each}

          {#if timeline.length === 0}
            <p class="text-slate-400 text-center py-4">No messages yet.</p>
          {/if}
        </div>

        <!-- Follow-up message form -->
        <div class="bg-slate-700/50 rounded-lg p-4 mb-4">
          <label for="follow-up" class="block text-sm font-medium text-slate-300 mb-2">
            Send a follow-up message
          </label>
          <textarea
            id="follow-up"
            bind:value={followUpText}
            rows="3"
            maxlength="10000"
            class="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded-lg text-white text-sm placeholder-slate-400 focus:outline-none focus:border-emerald-500 resize-none"
            placeholder="Type a follow-up message (encrypted end-to-end)..."
          ></textarea>
          {#if followUpError}
            <p class="text-red-400 text-xs mt-1">{followUpError}</p>
          {/if}
          {#if followUpSuccess}
            <p class="text-emerald-400 text-xs mt-1">✅ Message sent</p>
          {/if}
          <button
            onclick={sendFollowUp}
            disabled={sendingFollowUp || !followUpText.trim()}
            class="mt-2 bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white text-sm px-4 py-2 rounded-lg transition cursor-pointer"
          >
            {sendingFollowUp ? 'Sending...' : '📤 Send Message'}
          </button>
        </div>

        <button
          onclick={() => {
            cleanup();
            success = false;
            timeline = [];
            anonymousName = '';
            error = '';
            decryptionErrors = {};
            submissionStatus = '';
            slug = '';
            followUpText = '';
            orgPublicKey = '';
          }}
          class="w-full bg-slate-700 hover:bg-slate-600 text-white py-2 rounded-lg transition cursor-pointer"
        >
          Check Another Name
        </button>

      {:else}
        <form onsubmit={checkReplies}>
          <div class="mb-6">
            <label for="name" class="block text-sm font-medium text-slate-300 mb-2">
              Your Anonymous Identity
            </label>
            <input
              id="name"
              type="text"
              bind:value={anonymousName}
              required
              class="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
              placeholder="e.g., Purple Falcon-A1B2"
            />
            <p class="text-slate-500 text-xs mt-2">
              This was shown to you when you submitted your tip.
            </p>
          </div>

          <button
            type="submit"
            disabled={loading}
            class="w-full bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white py-3 rounded-lg font-medium transition cursor-pointer"
          >
            {loading ? 'Checking...' : '🔍 Check for Replies'}
          </button>
        </form>
      {/if}
    </div>

    <p class="text-center text-slate-500 text-sm mt-6">
      Want to submit a new tip?
      <a href="/" class="text-emerald-500 hover:underline ml-1">Find an organization</a>
    </p>
  </div>
</div>
