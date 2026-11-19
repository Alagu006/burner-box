<script>
  import { page } from '$app/stores';
  import {
    encryptForRecipient,
    generateKeyPair,
    encryptFile,
    encryptPrivateKey,
    generatePassphrase,
    encryptWithPGP,
    encryptFileWithPGP,
  } from '$lib/crypto';
  import {
    isSpeechSynthesisSupported,
    previewSpeech,
    stopSpeech,
    generateSyntheticAudioBlob,
  } from '$lib/tts';
  import {
    scanPII,
    redactMatch,
    redactAllMatches,
    generateHighlightedSegments,
  } from '$lib/pii_scanner';
  import { API_URL } from '$lib/api';
  import { t } from '$lib/i18n';

  let slug = $state('');
  let messageText = $state('');
  let piiDismissed = $state(false);
  let piiMatches = $derived(scanPII(messageText));
  let highlightedSegments = $derived(generateHighlightedSegments(messageText, piiMatches));

  function handleRedactSingle(match) {
    messageText = redactMatch(messageText, match);
  }

  function handleRedactAll() {
    messageText = redactAllMatches(messageText, piiMatches);
  }
  let enableReply = $state(false);
  let replyPublicKey = $state('');
  let replyPassphrase = $state('');
  let copiedPassphrase = $state(false);
  let copiedIdentity = $state(false);
  let selectedFiles = $state([]);
  let filePreviews = $state({}); // index → object URL (images only)
  let enableSyntheticAudio = $state(false);
  let isSpeaking = $state(false);
  let loading = $state(false);
  let success = $state(false);
  let error = $state('');
  let anonymousName = $state('');
  let submissionId = $state('');
  let filesUploaded = $state(0);
  let encryptionStatus = $state(''); // Shows encryption progress
  let orgPublicKey = $state('');
  let orgName = $state('');
  let orgEncryptionScheme = $state('libsodium'); // 'libsodium' | 'pgp'
  let welcomeMessage = $state('');
  let logoUrl = $state('');
  let customFields = $state([]);
  let customFieldValues = $state({});
  let deadlineClosed = $state(false);
  let deadlineDate = $state('');
  let proofData = $state(null);
  // Anti-spam: randomly-suffixed honeypot field generated per page load.
  // Avoids semantic names like "email" or "website" that trigger browser autofill.
  let honeypotFieldName = $state('hp_' + Math.random().toString(36).substring(2, 10));
  let honeypotValue = $state('');
  let renderedAt = $state(Date.now()); // Client page-load timestamp

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

  // Fetch organization's public key for encryption and customization
  async function fetchOrganizationPublicKey() {
    try {
      const response = await fetch(`${API_URL}/api/v1/submit/${slug}/public-key`);
      const data = await response.json();
      
      if (response.ok) {
        orgPublicKey = data.public_key;
        orgName = data.organization_name || '';
        orgEncryptionScheme = data.encryption_scheme || 'libsodium';
        welcomeMessage = data.welcome_message || '';
        logoUrl = data.logo_url || '';
        customFields = data.custom_fields || [];
        
        // Initialize customFieldValues keys
        const initialVals = {};
        for (const f of customFields) {
          initialVals[f.id] = '';
        }
        customFieldValues = initialVals;

        const schemeLabel = orgEncryptionScheme === 'pgp' ? 'PGP / OpenPGP' : 'libsodium';
        encryptionStatus = `${$t('submit.encryption_ready')} (${schemeLabel})`;
        if (data.closed) {
          deadlineClosed = true;
          deadlineDate = data.deadline || '';
          encryptionStatus = '⛔ ' + $t('submit.closed_title');
        }
      } else {
        encryptionStatus = '⚠️ ' + (data.error || 'Unknown error');
        orgPublicKey = '';
      }
    } catch (err) {
      encryptionStatus = '⚠️ ' + $t('submit.encryption_not_ready');
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

  function handlePlayAudioPreview() {
    if (!messageText.trim()) return;
    isSpeaking = true;
    previewSpeech(messageText.trim(), {
      onStart: () => { isSpeaking = true; },
      onEnd: () => { isSpeaking = false; },
      onError: () => { isSpeaking = false; },
    });
  }

  function handleStopAudioPreview() {
    stopSpeech();
    isSpeaking = false;
  }

  async function handleSubmit(e) {
    e.preventDefault();
    error = '';
    loading = true;
    encryptionStatus = $t('submit.encrypting');

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
        // Generate random passphrase to encrypt the reply private key before storing in localStorage
        replyPassphrase = generatePassphrase();
        const encKeyResult = await encryptPrivateKey(replyKeyPair.privateKey, replyPassphrase);
        localStorage.setItem('burnerbox_reply_private_key', JSON.stringify({
          encrypted: encKeyResult.encryptedPrivateKey,
          salt: encKeyResult.salt,
          nonce: encKeyResult.nonce,
        }));
        formData.append('reply_public_key', replyKeyPair.publicKey);
      }

      // Validate required custom fields
      for (const f of customFields) {
        if (f.required && (!customFieldValues[f.id] || !String(customFieldValues[f.id]).trim())) {
          error = `Please answer required field: "${f.label}"`;
          loading = false;
          encryptionStatus = '';
          return;
        }
      }

      // SPAM MITIGATION: Non-semantic dynamic honeypot field and client fill timestamp
      formData.append('honeypot_field', honeypotFieldName);
      formData.append(honeypotFieldName, honeypotValue);
      formData.append('rendered_at', String(renderedAt));

      // Prepare bundled payload (main message + custom field responses)
      let payloadToEncrypt = messageText.trim();
      if (customFields && customFields.length > 0) {
        const answers = {};
        let hasAnswers = false;
        for (const f of customFields) {
          const val = customFieldValues[f.id];
          if (val !== undefined && String(val).trim() !== '') {
            answers[f.label] = String(val).trim();
            hasAnswers = true;
          }
        }
        if (hasAnswers) {
          payloadToEncrypt = JSON.stringify({
            main_message: messageText.trim(),
            custom_fields: answers,
          });
        }
      }

      // Encrypt the bundled payload based on the organization's encryption scheme
      if (payloadToEncrypt) {
        if (orgEncryptionScheme === 'pgp') {
          const armoredCiphertext = await encryptWithPGP(payloadToEncrypt, orgPublicKey);
          formData.append('encrypted_message', armoredCiphertext);
          formData.append('encryption_meta', JSON.stringify({ scheme: 'pgp' }));
        } else {
          const encResult = await encryptForRecipient(payloadToEncrypt, orgPublicKey);
          const encryptionMeta = {
            scheme: 'libsodium',
            nonce: encResult.nonce,
            encryptedKey: encResult.encryptedKey,
            boxNonce: encResult.boxNonce,
            senderPublicKey: encResult.senderPublicKey,
          };
          formData.append('encrypted_message', encResult.ciphertext);
          formData.append('encryption_meta', JSON.stringify(encryptionMeta));
        }
      }

      // If synthetic audio option is enabled and message has content, synthesize audio file client-side
      const allFilesToEncrypt = [...selectedFiles];
      if (enableSyntheticAudio && messageText.trim()) {
        try {
          encryptionStatus = '🎙️ Generating synthetic audio version...';
          const audioBlob = await generateSyntheticAudioBlob(messageText.trim());
          const syntheticAudioFile = new File([audioBlob], 'synthetic-voice-message.wav', {
            type: 'audio/wav',
          });
          allFilesToEncrypt.push(syntheticAudioFile);
        } catch (audioErr) {
          console.warn('Could not generate synthetic audio blob:', audioErr);
        }
      }

      // Encrypt and append files client-side (defense-in-depth: server also encrypts)
      const clientEncryptionMeta = {};
      for (let i = 0; i < allFilesToEncrypt.length; i++) {
        const file = allFilesToEncrypt[i];
        try {
          const arrayBuffer = await file.arrayBuffer();
          if (orgEncryptionScheme === 'pgp') {
            const encResult = await encryptFileWithPGP(arrayBuffer, orgPublicKey);
            const encryptedBlob = new Blob([encResult], { type: 'application/octet-stream' });
            formData.append('files', encryptedBlob, file.name);
            clientEncryptionMeta[file.name] = { scheme: 'pgp' };
          } else {
            const encResult = await encryptFile(arrayBuffer, orgPublicKey);
            const encryptedBlob = new Blob([encResult.ciphertext], { type: 'application/octet-stream' });
            formData.append('files', encryptedBlob, file.name);
            clientEncryptionMeta[file.name] = {
              scheme: 'libsodium',
              nonce: encResult.nonce,
              encryptedKey: encResult.encryptedKey,
              boxNonce: encResult.boxNonce,
              senderPublicKey: encResult.senderPublicKey,
            };
          }
        } catch {
          // If encryption fails for a file, append it raw and let the server handle it
          formData.append('files', file);
        }
      }
      if (Object.keys(clientEncryptionMeta).length > 0) {
        formData.append('client_encryption_meta', JSON.stringify(clientEncryptionMeta));
      }

      encryptionStatus = $t('submit.sending');

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
      encryptionStatus = '✅ ' + $t('submit.success_title');

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
    const receiptObj = {
      version: '2.0',
      receipt_type: 'BurnerBox Cryptographic Submission Receipt',
      submission_id: proofData.submission_id,
      anonymous_name: anonymousName,
      timestamp: proofData.timestamp,
      payload_hash: proofData.hash,
      signature: proofData.signature,
      key_fingerprint: proofData.key_fingerprint,
      server_public_key: proofData.server_public_key || '',
      merkle_tree: {
        batch_id: proofData.batch_id || '',
        batch_number: proofData.batch_number || 1,
        leaf_index: proofData.leaf_index !== undefined ? proofData.leaf_index : 0,
        leaf_hash: proofData.leaf_hash || proofData.hash,
        status: proofData.merkle_status || 'open',
        inclusion_proof_url: `${window.location.origin}${proofData.inclusion_proof_endpoint || `/api/v1/submit/${slug}/proof/${proofData.submission_id}`}`,
        published_roots_url: `${window.location.origin}${proofData.published_roots_endpoint || `/api/v1/portal/${slug}/merkle-roots`}`,
      },
      verification_guide: {
        offline_tool: 'verify-receipt.html',
        instructions: 'Open verify-receipt.html in any browser (offline or online) and paste or load this file to independently verify your inclusion proof against the signed Merkle root.',
      },
    };

    const content = JSON.stringify(receiptObj, null, 2);
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `burnerbox-receipt-${proofData.submission_id}.json`;
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
      {$t('submit.quick_exit')}
    </button>
  </div>

  <div class="max-w-2xl mx-auto pt-16">
    
    {#if success}
      <!-- Success State -->
      <div class="bg-slate-800 rounded-lg p-8 shadow-xl text-center">
        <div class="text-5xl mb-4">✅</div>
        <h1 class="text-2xl font-bold text-emerald-500 mb-4">
          {$t('submit.success_title')}
        </h1>
        
        <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-4 mb-6 text-left">
          <p class="text-emerald-400 font-bold text-lg mb-2">
            {$t('submit.identity_label')}
          </p>
          <div class="flex items-center justify-between gap-3">
            <p class="text-white text-2xl font-mono font-bold">
              {anonymousName}
            </p>
            <button
              type="button"
              onclick={() => {
                navigator.clipboard.writeText(anonymousName);
                copiedIdentity = true;
                setTimeout(() => { copiedIdentity = false; }, 2000);
              }}
              class="bg-emerald-700 hover:bg-emerald-600 text-white text-xs px-3 py-1.5 rounded transition cursor-pointer"
            >
              {copiedIdentity ? '✅ Copied' : '📋 Copy'}
            </button>
          </div>
          <p class="text-slate-400 text-sm mt-3">
            {$t('submit.identity_warning')}
          </p>
        </div>

        {#if enableReply && replyPassphrase}
          <div class="bg-amber-950/60 border border-amber-500 rounded-lg p-4 mb-6 text-left">
            <p class="text-amber-400 font-bold text-lg mb-2">
              🔑 {$t('submit.passphrase_label')}
            </p>
            <div class="flex items-center justify-between gap-3 bg-slate-900/80 p-3 rounded border border-amber-600/50">
              <code class="text-amber-300 font-mono text-lg font-bold tracking-wide break-all">
                {replyPassphrase}
              </code>
              <button
                type="button"
                onclick={() => {
                  navigator.clipboard.writeText(replyPassphrase);
                  copiedPassphrase = true;
                  setTimeout(() => { copiedPassphrase = false; }, 2000);
                }}
                class="bg-amber-600 hover:bg-amber-500 text-white text-xs px-3 py-1.5 rounded transition cursor-pointer flex-shrink-0"
              >
                {copiedPassphrase ? '✅ Copied' : $t('submit.copy_passphrase')}
              </button>
            </div>
            <p class="text-amber-200/90 text-sm mt-3 font-medium">
              {$t('submit.passphrase_warning')}
            </p>
          </div>
        {/if}

        {#if filesUploaded > 0}
          <div class="bg-slate-700 rounded-lg p-4 mb-6 text-left">
            <p class="text-white font-medium mb-1">{$t('submit.files_uploaded')}</p>
            <p class="text-slate-400 text-sm">{filesUploaded} file(s) attached</p>
          </div>
        {/if}

        {#if proofData}
          <div class="bg-slate-700/50 rounded-lg p-4 mb-6 text-left space-y-2">
            <div class="flex items-center justify-between">
              <p class="text-white font-medium text-sm">{$t('submit.proof_title')}</p>
              <span class="bg-emerald-950/60 border border-emerald-800/60 text-emerald-400 text-[10px] px-2 py-0.5 rounded font-mono">
                🌳 Merkle Logged
              </span>
            </div>
            <p class="text-slate-400 text-xs">
              {$t('submit.proof_desc')}
            </p>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs bg-slate-800/80 p-3 rounded border border-slate-700 font-mono">
              <div>
                <span class="text-slate-500 block text-[10px]">PAYLOAD HASH</span>
                <span class="text-slate-300 truncate block">{proofData.hash?.substring(0, 24)}...</span>
              </div>
              <div>
                <span class="text-slate-500 block text-[10px]">KEY FINGERPRINT</span>
                <span class="text-slate-300">{proofData.key_fingerprint}</span>
              </div>
              <div>
                <span class="text-slate-500 block text-[10px]">MERKLE BATCH</span>
                <span class="text-emerald-400">Batch #{proofData.batch_number || 1} (Leaf #{proofData.leaf_index !== undefined ? proofData.leaf_index : 0})</span>
              </div>
              <div>
                <span class="text-slate-500 block text-[10px]">BATCH STATUS</span>
                <span class="text-amber-400">{proofData.merkle_status === 'sealed' ? '✅ Sealed & Signed' : '⏳ Open (Pending Seal)'}</span>
              </div>
            </div>

            <div class="pt-2 flex flex-wrap items-center gap-3">
              <button
                onclick={downloadProof}
                class="bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-semibold px-4 py-2 rounded-lg transition cursor-pointer flex items-center gap-1.5"
              >
                <span>💾</span> Download Signed Receipt (.json)
              </button>
              <a
                href="/verify-receipt.html"
                target="_blank"
                rel="noreferrer"
                class="text-xs text-slate-400 hover:text-emerald-400 underline"
              >
                Standalone Offline Verifier ↗
              </a>
            </div>
          </div>
        {/if}

        {#if enableReply}
          <div class="bg-slate-700 rounded-lg p-4 mb-6 text-left">
            <p class="text-white font-medium mb-2">{$t('submit.replies_enabled')}</p>
            <p class="text-slate-400 text-sm">
              {$t('submit.replies_desc')}
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
          {$t('submit.exit_safely')}
        </button>
      </div>

    {:else}
      <!-- Submission Form -->
      <div class="bg-slate-800 rounded-lg p-8 shadow-xl">
        {#if logoUrl}
          <div class="flex justify-center mb-4">
            <img
              src={logoUrl}
              alt="{orgName || 'Organization'} Logo"
              class="h-14 max-w-[240px] object-contain rounded-lg p-1 bg-white/5 border border-slate-700/60 shadow-md"
            />
          </div>
        {/if}

        <div class="text-center mb-6">
          <h1 class="text-2xl font-bold text-white">{$t('submit.title')}</h1>
          <p class="text-slate-400 text-sm mt-2">
            {$t('submit.subtitle')}
          </p>
          {#if orgName}
            <p class="text-slate-500 text-xs mt-1">
              {$t('submit.submitting_to')} <span class="text-emerald-400 font-medium">{orgName}</span>
            </p>
          {/if}
        </div>

        {#if welcomeMessage}
          <div class="bg-slate-700/40 border border-slate-600/60 rounded-lg p-4 mb-4 text-left">
            <p class="text-xs text-slate-300 whitespace-pre-line leading-relaxed">
              {welcomeMessage}
            </p>
          </div>
        {/if}

        <!-- Encryption Status Banner -->
        <div class="mb-4 p-3 rounded-lg {orgPublicKey ? 'bg-emerald-900/30 border border-emerald-700' : 'bg-yellow-900/30 border border-yellow-700'}">
          <p class="text-xs {orgPublicKey ? 'text-emerald-400' : 'text-yellow-400'}">
            {encryptionStatus || $t('submit.checking_encryption')}
          </p>
        </div>

        {#if error}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{error}</p>
          </div>
        {/if}

        {#if deadlineClosed}
          <div class="bg-red-900/30 border border-red-500 rounded-lg p-6 mb-4 text-center">
            <p class="text-red-400 font-bold text-lg mb-2">{$t('submit.closed_title')}</p>
            <p class="text-slate-400 text-sm">
              {$t('submit.closed_desc')}
              {#if deadlineDate}
                The deadline was {new Date(deadlineDate).toLocaleString()}.
              {/if}
            </p>
          </div>
        {:else}
        <form onsubmit={handleSubmit}>
          <!-- Honeypot anti-spam field (invisible to human users, traps automated bots; non-semantic random name avoids browser autofill) -->
          <div style="position: absolute; left: -9999px; opacity: 0; pointer-events: none;" aria-hidden="true" tabindex="-1">
            <label for={honeypotFieldName}>Leave this field blank</label>
            <input
              type="text"
              id={honeypotFieldName}
              name={honeypotFieldName}
              bind:value={honeypotValue}
              tabindex="-1"
              autocomplete="off"
            />
            <input
              type="hidden"
              name="honeypot_field"
              value={honeypotFieldName}
            />
          </div>

          <!-- Message Input with Real-Time Client-Side PII Inline Highlights -->
          <div class="mb-4">
            <div class="flex items-center justify-between mb-2">
              <label for="message" class="block text-sm font-medium text-slate-300">
                {$t('submit.message_label')}
              </label>
              {#if piiMatches.length > 0}
                <span class="inline-flex items-center gap-1.5 text-xs text-amber-400 bg-amber-950/70 border border-amber-800/80 px-2.5 py-0.5 rounded-full font-mono">
                  <span>⚠️</span> {piiMatches.length} identifying pattern{piiMatches.length > 1 ? 's' : ''} detected
                </span>
              {/if}
            </div>

            <div class="relative rounded-lg overflow-hidden border border-slate-600 focus-within:border-emerald-500 focus-within:ring-1 focus-within:ring-emerald-500 bg-slate-700">
              <!-- Inline Highlight Backdrop Layer (Underlines PII matches without obstructing text input) -->
              <div
                class="absolute inset-0 px-4 py-3 text-sm font-normal text-transparent pointer-events-none whitespace-pre-wrap break-words overflow-hidden leading-relaxed select-none"
                aria-hidden="true"
              >
                {#each highlightedSegments as seg}
                  {#if seg.isPII}
                    <mark class="bg-amber-400/25 text-transparent underline decoration-amber-400 decoration-wavy decoration-2 rounded-sm px-0.5">{seg.text}</mark>
                  {:else}
                    <span>{seg.text}</span>
                  {/if}
                {/each}
              </div>

              <!-- Foreground Transparent Textarea -->
              <textarea
                id="message"
                bind:value={messageText}
                rows="6"
                class="relative w-full px-4 py-3 bg-transparent text-white text-sm placeholder-slate-400 focus:outline-none resize-none leading-relaxed"
                placeholder={$t('submit.message_placeholder')}
              ></textarea>
            </div>
          </div>

          <!-- Advisory PII Warning & One-Click Redaction Panel (Client-Side Only, Zero Network) -->
          {#if piiMatches.length > 0 && !piiDismissed}
            <div class="mb-4 bg-amber-950/40 border border-amber-700/80 rounded-xl p-4 space-y-3">
              <div class="flex items-start justify-between gap-3">
                <div class="flex items-center gap-2">
                  <span class="text-base sm:text-lg">⚠️</span>
                  <h3 class="text-xs sm:text-sm font-semibold text-amber-300">
                    We noticed some things that might identify you — review before submitting
                  </h3>
                </div>
                <button
                  type="button"
                  onclick={() => piiDismissed = true}
                  class="text-xs text-amber-400/80 hover:text-amber-200 underline cursor-pointer flex-shrink-0"
                  title="Dismiss warning"
                >
                  Dismiss
                </button>
              </div>

              <!-- Mandatory Pattern Scanner Disclaimer -->
              <p class="text-xs text-amber-200/85 leading-relaxed bg-amber-900/30 p-2.5 rounded-lg border border-amber-800/40">
                ℹ️ <em>This is a basic pattern scanner, not a substitute for reviewing your own message carefully — it won't catch everything.</em>
              </p>

              <!-- List of Detected PII Matches with One-Click Redact Option -->
              <div class="space-y-2 max-h-56 overflow-y-auto pr-1">
                {#each piiMatches as match (match.id)}
                  <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 rounded-lg bg-slate-900/80 border border-amber-900/50 text-xs">
                    <div class="space-y-1 min-w-0">
                      <div class="flex items-center gap-2">
                        <span class="bg-amber-900/80 text-amber-300 font-mono text-[10px] px-2 py-0.5 rounded border border-amber-700/60 font-semibold uppercase">
                          {match.typeLabel}
                        </span>
                        <span class="font-mono text-white truncate max-w-xs block font-medium">
                          "{match.text}"
                        </span>
                      </div>
                      <p class="text-slate-400 text-[11px] leading-tight">
                        {match.reason}
                      </p>
                    </div>
                    <button
                      type="button"
                      onclick={() => handleRedactSingle(match)}
                      class="bg-amber-700 hover:bg-amber-600 text-white font-medium text-xs px-3 py-1.5 rounded transition cursor-pointer flex-shrink-0 self-start sm:self-center"
                    >
                      Redact
                    </button>
                  </div>
                {/each}
              </div>

              <div class="pt-2 border-t border-amber-800/50 flex items-center justify-between gap-3 flex-wrap">
                <span class="text-[11px] text-slate-400">
                  Advisory only: You can redact items above or submit them if intended.
                </span>
                <button
                  type="button"
                  onclick={handleRedactAll}
                  class="bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs px-3.5 py-1.5 rounded-lg transition cursor-pointer flex items-center gap-1.5 shadow"
                >
                  <span>🛡️</span> Redact All ({piiMatches.length})
                </button>
              </div>
            </div>
          {/if}

          <!-- Synthetic Voice Spoken Audio Option (Client-Side Only, Zero Mic) -->
          <div class="mb-4 bg-slate-700/40 border border-slate-600/80 rounded-xl p-4 space-y-3">
            <div class="flex items-start justify-between gap-3">
              <div class="flex items-center gap-2.5">
                <input
                  type="checkbox"
                  id="enable-audio"
                  bind:checked={enableSyntheticAudio}
                  class="w-4 h-4 rounded bg-slate-700 border-slate-600 text-emerald-500 focus:ring-emerald-500 cursor-pointer"
                />
                <label for="enable-audio" class="text-xs sm:text-sm font-medium text-slate-200 cursor-pointer select-none">
                  🎙️ Include Computer-Generated Spoken Version
                </label>
              </div>
              <span class="text-[10px] text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40 font-mono flex-shrink-0">
                🔒 100% Synthetic
              </span>
            </div>

            <!-- MANDATORY PRIVACY LABEL -->
            <div class="text-xs text-amber-200/90 bg-amber-950/40 border border-amber-800/60 rounded-lg p-3 flex items-start gap-2.5">
              <span class="text-base flex-shrink-0">🛡️</span>
              <p class="leading-relaxed">
                <strong>Privacy Notice:</strong> This uses a computer-generated voice — your actual voice is never recorded or uploaded.
              </p>
            </div>

            {#if enableSyntheticAudio}
              <div class="pt-2 border-t border-slate-600/60 space-y-2.5">
                <p class="text-xs text-slate-300">
                  Preview how the computer-generated system voice will read your message:
                </p>

                <div class="flex flex-wrap items-center gap-3">
                  {#if isSpeaking}
                    <button
                      type="button"
                      onclick={handleStopAudioPreview}
                      class="bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold px-3.5 py-2 rounded-lg transition cursor-pointer flex items-center gap-1.5 shadow"
                    >
                      <span>⏹️</span> Stop Audio Preview
                    </button>
                  {:else}
                    <button
                      type="button"
                      onclick={handlePlayAudioPreview}
                      disabled={!messageText.trim()}
                      class="bg-slate-600 hover:bg-slate-500 disabled:opacity-40 text-white text-xs font-semibold px-3.5 py-2 rounded-lg transition cursor-pointer flex items-center gap-1.5 shadow"
                    >
                      <span>🔊</span> Preview Spoken Voice
                    </button>
                  {/if}

                  {#if messageText.trim()}
                    <span class="text-xs text-slate-400">
                      ({messageText.trim().split(/\s+/).length} word{messageText.trim().split(/\s+/).length === 1 ? '' : 's'} · ~{Math.max(1, Math.round(messageText.trim().split(/\s+/).length * 0.45))}s)
                    </span>
                  {:else}
                    <span class="text-xs text-slate-400 italic">
                      Type your message above to preview audio
                    </span>
                  {/if}
                </div>
              </div>
            {/if}
          </div>

          <!-- Dynamic Custom Fields (Bundled into encrypted payload) -->
          {#if customFields.length > 0}
            <div class="mb-5 space-y-4 border-t border-slate-700/80 pt-4">
              <div class="flex items-center gap-2">
                <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Additional Details
                </span>
                <span class="text-[10px] text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                  🔒 End-to-End Encrypted
                </span>
              </div>

              {#each customFields as field (field.id)}
                <div class="space-y-1 text-left">
                  <label for={`custom-field-${field.id}`} class="block text-xs font-medium text-slate-300">
                    {field.label}
                    {#if field.required}
                      <span class="text-rose-400">*</span>
                    {/if}
                  </label>

                  {#if field.field_type === 'textarea'}
                    <textarea
                      id={`custom-field-${field.id}`}
                      bind:value={customFieldValues[field.id]}
                      rows="3"
                      placeholder="Your response..."
                      class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-xs text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 resize-none"
                    ></textarea>
                  {:else if field.field_type === 'select'}
                    <select
                      id={`custom-field-${field.id}`}
                      bind:value={customFieldValues[field.id]}
                      class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-xs text-white focus:outline-none focus:border-emerald-500"
                    >
                      <option value="">-- Select an option --</option>
                      {#each field.options || [] as opt}
                        <option value={opt}>{opt}</option>
                      {/each}
                    </select>
                  {:else}
                    <input
                      id={`custom-field-${field.id}`}
                      type="text"
                      bind:value={customFieldValues[field.id]}
                      placeholder="Your response..."
                      class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-xs text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
                    />
                  {/if}
                </div>
              {/each}
            </div>
          {/if}

          <!-- File Upload -->
          <div class="mb-4">
            <label for="file-upload" class="block text-sm font-medium text-slate-300 mb-2">
              {$t('submit.attach_files')}
            </label>
            <input
              id="file-upload"
              type="file"
              multiple
              onchange={handleFileSelect}
              accept=".jpg,.jpeg,.png,.gif,.pdf,.txt,.doc,.docx,.mp4,.mp3,.wav,.zip"
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
              {$t('submit.max_file_hint')}
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
                {$t('submit.allow_replies')}
              </span>
            </label>
            {#if enableReply}
              <p class="text-slate-500 text-xs mt-2 ml-7">
                {$t('submit.reply_hint')}
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
              {$t('submit.encryption_not_ready')}
            {:else}
              {$t('submit.send_btn')}
            {/if}
          </button>
        </form>
        {/if}

        <!-- Security Note -->
        <div class="mt-6 p-4 bg-slate-700/50 rounded-lg">
          <p class="text-slate-400 text-xs">
            {$t('submit.security_note')}
          </p>
        </div>
      </div>
    {/if}
  </div>
</div>