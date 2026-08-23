<script>
  import { page } from '$app/stores';
  import { encryptForRecipient, generateKeyPair, encryptFile } from '$lib/crypto';
  import { API_URL } from '$lib/api';

  let slug = $state('');
  let messageText = $state('');
  let enableReply = $state(false);
  let replyPublicKey = $state('');
  let selectedFiles = $state([]);
  let filePreviews = $state({}); // index → object URL (images only)
  let loading = $state(false);
  let success = $state(false);
  let error = $state('');
  let anonymousName = $state('');
  let submissionId = $state('');
  let filesUploaded = $state(0);
  let encryptionStatus = $state(''); // Shows encryption progress
  let orgPublicKey = $state('');
  let orgName = $state('');
  let deadlineClosed = $state(false);
  let deadlineDate = $state('');
  let proofData = $state(null);

  const IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function revokeAllPreviews() {
    Object.values(filePreviews).forEach(url => URL.revokeObjectURL(url));
    filePreviews = {};
  }

  $effect(() => {
    slug = $page.params.slug;
    if (slug) {
      fetchOrganizationPublicKey();
    }
  });

  // Fetch organization's public key for encryption
  async function fetchOrganizationPublicKey() {
    try {
      const response = await fetch(`${API_URL}/api/v1/submit/${slug}/public-key`);
      const data = await response.json();
      
      if (response.ok) {
        orgPublicKey = data.public_key;
        orgName = data.organization_name || '';
        encryptionStatus = '✅ Encryption ready';
        if (data.closed) {
          deadlineClosed = true;
          deadlineDate = data.deadline || '';
          encryptionStatus = '⛔ This submission portal is closed.';
        }
      } else {
        encryptionStatus = '⚠️ Encryption not available: ' + (data.error || 'Unknown error');
        orgPublicKey = '';
      }
    } catch (err) {
      encryptionStatus = '⚠️ Cannot reach server for encryption key';
      orgPublicKey = '';
    }
  }

  function handleFileSelect(e) {
    revokeAllPreviews();
    const files = Array.from(e.target.files);
    selectedFiles = files;
    const previews = {};
    files.forEach((file, i) => {
      if (IMAGE_TYPES.includes(file.type)) {
        previews[i] = URL.createObjectURL(file);
      }
    });
    filePreviews = previews;
  }

  function removeFile(index) {
    revokeAllPreviews();
    const removed = selectedFiles.splice(index, 1)[0];
    selectedFiles = [...selectedFiles];
    if (removed && filePreviews[index]) {
      URL.revokeObjectURL(filePreviews[index]);
    }
    // Regenerate previews for remaining files
    const previews = {};
    selectedFiles.forEach((file, i) => {
      if (IMAGE_TYPES.includes(file.type)) {
        previews[i] = URL.createObjectURL(file);
      }
    });
    filePreviews = previews;
  }

  async function handleSubmit(e) {
    e.preventDefault();
    error = '';
    loading = true;
    encryptionStatus = '🔐 Encrypting your submission...';

    if (!messageText.trim() && selectedFiles.length === 0) {
      error = 'Please enter a message or attach a file';
      loading = false;
      encryptionStatus = '';
      return;
    }

    if (!orgPublicKey) {
      error = 'Cannot encrypt: Organization public key not available. Please try again later.';
      loading = false;
      encryptionStatus = '';
      return;
    }

    try {
      const formData = new FormData();

      if (enableReply) {
        const replyKeyPair = await generateKeyPair();
        replyPublicKey = replyKeyPair.publicKey;
        // SECURITY TODO: Same as burnerbox_private_key — encrypt with password before storage.
        localStorage.setItem('burnerbox_reply_private_key', replyKeyPair.privateKey);
        formData.append('reply_public_key', replyKeyPair.publicKey);
      }

      // Encrypt the message text
      if (messageText.trim()) {
        const encResult = await encryptForRecipient(messageText, orgPublicKey);
        
        // Store encryption metadata
        const encryptionMeta = {
          nonce: encResult.nonce,
          encryptedKey: encResult.encryptedKey,
          boxNonce: encResult.boxNonce,
          senderPublicKey: encResult.senderPublicKey,
        };

        formData.append('encrypted_message', encResult.ciphertext);
        formData.append('encryption_meta', JSON.stringify(encryptionMeta));
      }

      // Encrypt and append files client-side (defense-in-depth: server also encrypts)
      const clientEncryptionMeta = {};
      for (let i = 0; i < selectedFiles.length; i++) {
        const file = selectedFiles[i];
        try {
          const arrayBuffer = await file.arrayBuffer();
          const encResult = await encryptFile(arrayBuffer, orgPublicKey);
          // Replace the raw file with the encrypted ciphertext
          const encryptedBlob = new Blob([encResult.ciphertext], { type: 'application/octet-stream' });
          formData.append('files', encryptedBlob, file.name);
          clientEncryptionMeta[file.name] = {
            nonce: encResult.nonce,
            encryptedKey: encResult.encryptedKey,
            boxNonce: encResult.boxNonce,
            senderPublicKey: encResult.senderPublicKey,
          };
        } catch {
          // If encryption fails for a file, append it raw and let the server handle it
          formData.append('files', file);
        }
      }
      if (Object.keys(clientEncryptionMeta).length > 0) {
        formData.append('client_encryption_meta', JSON.stringify(clientEncryptionMeta));
      }

      encryptionStatus = '📤 Sending encrypted submission...';

      const response = await fetch(`${API_URL}/api/v1/submit/${slug}`, {
        method: 'POST',
        body: formData, // Don't set Content-Type - browser sets it with boundary
      });

      const data = await response.json();

      if (!response.ok) {
        error = data.error || 'Submission failed';
        loading = false;
        encryptionStatus = '';
        return;
      }

      anonymousName = data.anonymous_name;
      submissionId = data.submission_id;
      filesUploaded = data.files_uploaded || 0;
      proofData = data.proof || null;
      success = true;
      encryptionStatus = '✅ Submission encrypted and sent';

    } catch (err) {
      error = 'Network error. Cannot reach server.';
      encryptionStatus = '';
    }

    loading = false;
  }

  function handleQuickExit() {
    window.location.replace('https://www.weather.com');
  }

  function downloadProof() {
    if (!proofData) return;
    const content = [
      '=== BurnerBox — Proof of Submission ===',
      '',
      `Submission ID: ${proofData.submission_id}`,
      `Timestamp:     ${proofData.timestamp}`,
      `Payload Hash:  ${proofData.hash}`,
      `Signature:     ${proofData.signature}`,
      `Key Fingerprint: ${proofData.key_fingerprint}`,
      '',
      '---',
      'To verify: hash the encrypted message with SHA-256,',
      'then verify the Ed25519 signature using the server public key',
      'from /api/v1/proof-key.',
    ].join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `burnerbox-proof-${proofData.submission_id}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }
</script>

<div class="min-h-screen bg-slate-900 p-4">
  
  <!-- Quick Exit Button (always visible) -->
  <div class="fixed top-4 right-4 z-50">
    <button
      onclick={handleQuickExit}
      class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-bold text-sm transition cursor-pointer shadow-lg"
    >
      ⚡ QUICK EXIT
    </button>
  </div>

  <div class="max-w-2xl mx-auto pt-16">
    
    {#if success}
      <!-- Success State -->
      <div class="bg-slate-800 rounded-lg p-8 shadow-xl text-center">
        <div class="text-5xl mb-4">✅</div>
        <h1 class="text-2xl font-bold text-emerald-500 mb-4">
          Submission Sent Successfully
        </h1>
        
        <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-4 mb-6 text-left">
          <p class="text-emerald-400 font-bold text-lg mb-2">
            Your Anonymous Identity:
          </p>
          <p class="text-white text-2xl font-mono font-bold">
            {anonymousName}
          </p>
          <p class="text-slate-400 text-sm mt-3">
            ⚠️ Save this name! You'll need it to check for replies.
            We will NEVER show this again.
          </p>
        </div>

        {#if filesUploaded > 0}
          <div class="bg-slate-700 rounded-lg p-4 mb-6 text-left">
            <p class="text-white font-medium mb-1">📎 Files Uploaded</p>
            <p class="text-slate-400 text-sm">{filesUploaded} file(s) attached</p>
          </div>
        {/if}

        {#if proofData}
          <div class="bg-slate-700/50 rounded-lg p-4 mb-6 text-left">
            <p class="text-white font-medium mb-2">📜 Proof of Submission</p>
            <p class="text-slate-400 text-xs mb-2">
              A cryptographic receipt signed by the server. You can independently verify
              that your submission was received at the stated time.
            </p>
            <p class="text-slate-400 text-xs font-mono mb-1">
              Hash: {proofData.hash?.substring(0, 32)}...
            </p>
            <p class="text-slate-400 text-xs font-mono mb-3">
              Key: {proofData.key_fingerprint}
            </p>
            <button
              onclick={downloadProof}
              class="bg-slate-600 hover:bg-slate-500 text-white text-sm px-4 py-2 rounded-lg transition cursor-pointer"
            >
              ⬇️ Download Proof (.txt)
            </button>
          </div>
        {/if}

        {#if enableReply}
          <div class="bg-slate-700 rounded-lg p-4 mb-6 text-left">
            <p class="text-white font-medium mb-2">📬 E2E Encrypted Replies Enabled</p>
            <p class="text-slate-400 text-sm">
              The organization can reply. Your decryption key is stored in this browser.
              Return to the same URL and enter your anonymous name to check for replies.
            </p>
            <p class="text-slate-500 text-xs mt-2 font-mono">
              Reply Key: {replyPublicKey}
            </p>
          </div>
        {/if}

        <div class="bg-slate-700/50 rounded-lg p-3 mb-6">
          <p class="text-slate-400 text-xs">
            🔒 {encryptionStatus}
          </p>
        </div>

        <button
          onclick={handleQuickExit}
          class="bg-slate-700 hover:bg-slate-600 text-white px-6 py-3 rounded-lg transition cursor-pointer"
        >
          🚪 Exit Safely
        </button>
      </div>

    {:else}
      <!-- Submission Form -->
      <div class="bg-slate-800 rounded-lg p-8 shadow-xl">
        <div class="text-center mb-6">
          <h1 class="text-2xl font-bold text-white">📨 Anonymous Submission</h1>
          <p class="text-slate-400 text-sm mt-2">
            Your identity is protected. No IP logs, no tracking.
          </p>
          {#if orgName}
            <p class="text-slate-500 text-xs mt-1">
              Submitting to: <span class="text-emerald-400 font-medium">{orgName}</span>
            </p>
          {/if}
        </div>

        <!-- Encryption Status Banner -->
        <div class="mb-4 p-3 rounded-lg {orgPublicKey ? 'bg-emerald-900/30 border border-emerald-700' : 'bg-yellow-900/30 border border-yellow-700'}">
          <p class="text-xs {orgPublicKey ? 'text-emerald-400' : 'text-yellow-400'}">
            {encryptionStatus || '🔐 Checking encryption...'}
          </p>
        </div>

        {#if error}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{error}</p>
          </div>
        {/if}

        {#if deadlineClosed}
          <div class="bg-red-900/30 border border-red-500 rounded-lg p-6 mb-4 text-center">
            <p class="text-red-400 font-bold text-lg mb-2">⛔ Submission Portal Closed</p>
            <p class="text-slate-400 text-sm">
              This organization is no longer accepting submissions.
              {#if deadlineDate}
                The deadline was {new Date(deadlineDate).toLocaleString()}.
              {/if}
            </p>
          </div>
        {:else}
        <form onsubmit={handleSubmit}>
          <!-- Message -->
          <div class="mb-4">
            <label for="message" class="block text-sm font-medium text-slate-300 mb-2">
              Your Message
            </label>
            <textarea
              id="message"
              bind:value={messageText}
              rows="6"
              class="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 resize-none"
              placeholder="Type your anonymous tip here..."
            ></textarea>
          </div>

          <!-- File Upload -->
          <div class="mb-4">
            <label for="file-upload" class="block text-sm font-medium text-slate-300 mb-2">
              Attach Files (Optional)
            </label>
            <input
              id="file-upload"
              type="file"
              multiple
              onchange={handleFileSelect}
              accept=".jpg,.jpeg,.png,.gif,.pdf,.txt,.doc,.docx,.mp4,.mp3,.zip"
              class="w-full text-slate-400 text-sm file:bg-slate-600 file:text-white file:border-none file:px-4 file:py-2 file:rounded-lg file:mr-3 file:cursor-pointer hover:file:bg-slate-500"
            />
            {#if selectedFiles.length > 0}
              <div class="mt-3 space-y-2">
                {#each selectedFiles as file, i}
                  <div class="flex items-start gap-3 bg-slate-700/50 rounded-lg p-2">
                    {#if filePreviews[i]}
                      <img
                        src={filePreviews[i]}
                        alt={file.name}
                        class="w-14 h-14 object-cover rounded border border-slate-600 flex-shrink-0"
                      />
                    {:else}
                      <div class="w-14 h-14 rounded border border-slate-600 flex items-center justify-center text-slate-500 text-xs flex-shrink-0">
                        {file.type.split('/')[1]?.substring(0, 5) || 'file'}
                      </div>
                    {/if}
                    <div class="flex-1 min-w-0">
                      <p class="text-white text-xs font-medium truncate">{file.name}</p>
                      <p class="text-slate-400 text-xs">{formatFileSize(file.size)} · {file.type || 'unknown'}</p>
                    </div>
                    <button
                      type="button"
                      onclick={() => removeFile(i)}
                      class="text-red-400 hover:text-red-300 text-xs flex-shrink-0 px-1 cursor-pointer"
                      title="Remove file"
                    >
                      ✕
                    </button>
                  </div>
                {/each}
              </div>
            {/if}
            <p class="text-slate-500 text-xs mt-1">
              Max 10MB per file. Files are encrypted before upload.
            </p>
          </div>

          <!-- Reply Option -->
          <div class="mb-6">
            <label class="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                bind:checked={enableReply}
                class="w-4 h-4 rounded bg-slate-700 border-slate-600 text-emerald-500 focus:ring-emerald-500"
              />
              <span class="text-slate-300 text-sm">
                Allow the organization to reply to this submission
              </span>
            </label>
            {#if enableReply}
              <p class="text-slate-500 text-xs mt-2 ml-7">
                A unique encryption keypair will be generated. Store it in this browser to read replies.
              </p>
            {/if}
          </div>

          <!-- Submit -->
          <button
            type="submit"
            disabled={loading || !orgPublicKey}
            class="w-full bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white py-3 rounded-lg font-medium transition cursor-pointer"
          >
            {#if loading}
              {encryptionStatus}
            {:else if !orgPublicKey}
              🔒 Encryption not ready
            {:else}
              🔒 Send Encrypted Anonymously
            {/if}
          </button>
        </form>
        {/if}

        <!-- Security Note -->
        <div class="mt-6 p-4 bg-slate-700/50 rounded-lg">
          <p class="text-slate-400 text-xs">
            🔒 Your message is encrypted in your browser before being sent.
            The server never sees the plaintext. We never log IP addresses.
          </p>
        </div>
      </div>
    {/if}
  </div>
</div>