<script>
  import { decryptFromSender, encryptForRecipient, decryptPrivateKey } from '$lib/crypto';
  import { API_URL, WS_URL } from '$lib/api';

  let anonymousName = $state('');
  let passphrase = $state('');
  let unlockedPrivateKey = $state('');
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
  let merkleProofData = $state(null);

  function downloadSealedReceipt() {
    if (!merkleProofData) return;
    const receiptObj = {
      version: '2.0',
      receipt_type: 'BurnerBox Sealed Cryptographic Inclusion Receipt',
      submission_id: merkleProofData.submission_id,
      anonymous_name: anonymousName,
      status: merkleProofData.status,
      leaf_index: merkleProofData.leaf_index,
      leaf_hash: merkleProofData.leaf_hash,
      batch_id: merkleProofData.batch_id,
      batch_number: merkleProofData.batch_number,
      root_hash: merkleProofData.root_hash,
      root_signature: merkleProofData.root_signature,
      key_fingerprint: merkleProofData.key_fingerprint,
      server_public_key: merkleProofData.server_public_key,
      sealed_at: merkleProofData.sealed_at,
      inclusion_proof: merkleProofData.inclusion_proof || [],
      verification_guide: {
        offline_tool: 'verify-receipt.html',
        instructions: 'Open verify-receipt.html in any browser (offline or online) and paste or load this file to independently recompute and verify your Merkle inclusion path against the server signed root.',
      },
    };

    const blob = new Blob([JSON.stringify(receiptObj, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `burnerbox-sealed-receipt-${merkleProofData.submission_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function unlockStoredPrivateKey(enteredPassphrase) {
    const rawStoredKey = localStorage.getItem('burnerbox_reply_private_key');
    if (!rawStoredKey) {
      return { key: null, error: 'No decryption key stored in this browser. Please use the same device & browser used when submitting.' };
    }

    try {
      const parsed = JSON.parse(rawStoredKey);
      if (parsed.encrypted && parsed.salt && parsed.nonce) {
        if (!enteredPassphrase.trim()) {
          return { key: null, error: 'Please enter your passphrase to unlock replies.' };
        }
        try {
          const decryptedKey = await decryptPrivateKey(parsed.encrypted, parsed.salt, parsed.nonce, enteredPassphrase.trim());
          return { key: decryptedKey, error: null };
        } catch {
          return { key: null, error: 'Invalid passphrase. Could not unlock reply decryption key.' };
        }
      }
    } catch {
      // Legacy unencrypted key format
      return { key: rawStoredKey, error: null };
    }
    return { key: rawStoredKey, error: null };
  }

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

    // Attempt to unlock private key if stored
    const unlockResult = await unlockStoredPrivateKey(passphrase);
    if (unlockResult.error && localStorage.getItem('burnerbox_reply_private_key')) {
      error = unlockResult.error;
      loading = false;
      return;
    }
    unlockedPrivateKey = unlockResult.key || '';

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

      // Fetch Merkle inclusion proof if available
      try {
        const proofResp = await fetch(`${API_URL}/api/v1/submit/inclusion-proof?submission_id=${encodeURIComponent(submissionId)}`);
        if (proofResp.ok) {
          merkleProofData = await proofResp.json();
        }
      } catch {
        merkleProofData = null;
      }

    } catch (err) {
      error = 'Network error. Cannot reach server.';
    }

    loading = false;
  }

  async function decryptTimeline(entries) {
    if (!unlockedPrivateKey) {
      entries.forEach((entry, i) => {
        if (entry.encrypted_text) {
          decryptionErrors[i] = 'No unlocked decryption key. Please enter your passphrase to decrypt.';
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
          unlockedPrivateKey
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

        <div class="flex items-center justify-between bg-slate-700/50 rounded-lg p-3 mb-4">
          <div class="flex items-center gap-2 text-sm">
            <span class="text-slate-400">Status:</span>
            <span class="text-white font-medium">{statusLabel(submissionStatus)}</span>
            {#if statusConnected}
              <span class="text-emerald-400 text-xs">● Live</span>
            {:else}
              <span class="text-slate-500 text-xs">● Polling{lastPollTime ? ` (${lastPollTime})` : ''}</span>
            {/if}
          </div>
          {#if unlockedPrivateKey}
            <span class="bg-emerald-900/60 text-emerald-300 text-xs px-2.5 py-1 rounded-full border border-emerald-500/40">
              🔓 Reply Key Unlocked
            </span>
          {:else}
            <span class="bg-amber-900/60 text-amber-300 text-xs px-2.5 py-1 rounded-full border border-amber-500/40">
              🔒 Locked (No Key)
            </span>
          {/if}
        </div>

        <!-- Merkle Tree Inclusion Proof Status Card -->
        {#if merkleProofData}
          <div class="bg-slate-800 border border-slate-700 rounded-xl p-4 mb-4 space-y-2.5">
            <div class="flex items-center justify-between">
              <h3 class="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
                <span>🌳 Cryptographic Batch Log (Merkle Tree)</span>
              </h3>
              {#if merkleProofData.status === 'sealed'}
                <span class="bg-emerald-950/80 border border-emerald-700 text-emerald-400 text-[10px] px-2 py-0.5 rounded font-mono font-medium">
                  ✅ Sealed & Signed
                </span>
              {:else}
                <span class="bg-amber-950/80 border border-amber-700 text-amber-300 text-[10px] px-2 py-0.5 rounded font-mono font-medium">
                  ⏳ Queued (Batch #{merkleProofData.batch_number || 1})
                </span>
              {/if}
            </div>

            {#if merkleProofData.status === 'sealed'}
              <p class="text-xs text-slate-300">
                Your submission is permanently sealed in Batch #{merkleProofData.batch_number}. The server has published the Ed25519-signed Merkle root.
              </p>
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs bg-slate-900/90 p-3 rounded-lg border border-slate-700/80 font-mono">
                <div>
                  <span class="text-slate-500 block text-[10px]">SEALED ROOT HASH</span>
                  <span class="text-emerald-400 truncate block">{merkleProofData.root_hash?.substring(0, 24)}...</span>
                </div>
                <div>
                  <span class="text-slate-500 block text-[10px]">LEAF INDEX IN TREE</span>
                  <span class="text-slate-300">Leaf #{merkleProofData.leaf_index} of {merkleProofData.total_leaves}</span>
                </div>
                <div>
                  <span class="text-slate-500 block text-[10px]">KEY FINGERPRINT</span>
                  <span class="text-slate-300">{merkleProofData.key_fingerprint}</span>
                </div>
                <div>
                  <span class="text-slate-500 block text-[10px]">INCLUSION PATH</span>
                  <span class="text-blue-400">{merkleProofData.inclusion_proof?.length || 0} sibling step(s)</span>
                </div>
              </div>

              <div class="pt-1 flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onclick={downloadSealedReceipt}
                  class="bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-semibold px-3.5 py-1.5 rounded-lg transition cursor-pointer flex items-center gap-1.5 shadow"
                >
                  <span>📥</span> Download Sealed Merkle Receipt (.json)
                </button>
                <a
                  href="/verify-receipt.html"
                  target="_blank"
                  rel="noreferrer"
                  class="text-xs text-slate-400 hover:text-emerald-400 underline"
                >
                  Verify in Offline Tool ↗
                </a>
              </div>
            {:else}
              <p class="text-xs text-slate-400">
                Your submission is currently in open Batch #{merkleProofData.batch_number} (Leaf #{merkleProofData.leaf_index}). When the hourly sealer runs, your full cryptographic inclusion proof and signed root will be available here.
              </p>
            {/if}
          </div>
        {/if}

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
            passphrase = '';
            unlockedPrivateKey = '';
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
          <div class="mb-4">
            <label for="name" class="block text-sm font-medium text-slate-300 mb-2">
              Your Anonymous Identity
            </label>
            <input
              id="name"
              type="text"
              bind:value={anonymousName}
              required
              class="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 font-mono"
              placeholder="e.g., Purple Falcon-A1B2"
            />
            <p class="text-slate-500 text-xs mt-2">
              This was shown to you when you submitted your tip.
            </p>
          </div>

          <div class="mb-6">
            <label for="passphrase" class="block text-sm font-medium text-slate-300 mb-2">
              Decryption Passphrase
            </label>
            <input
              id="passphrase"
              type="text"
              bind:value={passphrase}
              class="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 font-mono"
              placeholder="e.g., coral-haven-flame-1234"
            />
            <p class="text-slate-500 text-xs mt-2">
              The secret passphrase shown when you enabled replies during submission.
            </p>
          </div>

          <button
            type="submit"
            disabled={loading}
            class="w-full bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white py-3 rounded-lg font-medium transition cursor-pointer"
          >
            {loading ? 'Unlocking & Checking...' : '🔍 Unlock & Check for Replies'}
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
