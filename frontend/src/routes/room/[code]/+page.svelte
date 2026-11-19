<script>
  import { page } from '$app/stores';
  import { encryptRoomMessage, decryptRoomMessage, encryptRoomFile, decryptRoomFile, encryptRoomReaction, decryptRoomReaction } from '$lib/crypto';
  import { API_URL, WS_URL } from '$lib/api';
  import { onMount, onDestroy } from 'svelte';

  let roomCode = $state('');
  let roomKey = $state('');
  let keyError = $state('');
  let passwordPrompt = $state(false);
  let roomPassword = $state('');
  let ws = $state(null);
  let connected = $state(false);
  let messages = $state([]);
  let inputText = $state('');
  let selfDestruct = $state(0); // 0 = never, else seconds
  let senderTag = $state('');
  let error = $state('');
  let chatEl = $state();
  let burnTimers = [];

  // Feature 2: participant count
  let participantCount = $state(0);
  let participantMax = $state(10);
  let participantText = $state('0 of 10 slots');

  // Feature 3: typing indicator
  let displayName = $state('');
  let typingUsers = $state(new Map()); // display_name -> timeout
  let typingInputTimeout = null;

  // Feature 4: message reactions
  let emojiPickerMsgId = $state(null);
  const reactionEmojis = ['👍', '❤️', '😂', '🔥', '👀', '✅', '❌', '🎉', '🤔', '💪'];

  // Feature 5: room revival
  let revivalProposal = $state(null); // {proposal_id, confirmations, required, total, proposed_by}

  // File upload state
  let fileInput = $state(null);
  let uploading = $state(false);

  // Room creator capability state
  let isCreator = $state(false);
  let burningRoom = $state(false);

  async function handleBurnRoom() {
    if (!confirm('Are you sure you want to permanently destroy this room and all its messages? This action cannot be undone.')) {
      return;
    }
    const token = sessionStorage.getItem('bb_creator_token_' + roomCode);
    if (!token) {
      alert('Creator token not found in this browser tab.');
      return;
    }
    burningRoom = true;
    try {
      const resp = await fetch(`${API_URL}/api/v1/rooms/${roomCode}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (resp.ok) {
        sessionStorage.removeItem('bb_creator_token_' + roomCode);
        window.location.replace('/');
      } else {
        const d = await resp.json().catch(() => ({}));
        alert(d.error || 'Failed to destroy room');
      }
    } catch (err) {
      alert('Network error while attempting to destroy room');
    } finally {
      burningRoom = false;
    }
  }

  const burnOptions = [
    { value: 0, label: 'No burn' },
    { value: 10, label: '10 seconds' },
    { value: 60, label: '1 minute' },
    { value: 300, label: '5 minutes' },
    { value: 600, label: '10 minutes' },
  ];

  function scheduleBurn(message) {
    if (!message.ttl || message.ttl <= 0 || !message.createdAt) return;
    const expiresAt = new Date(message.createdAt).getTime() + message.ttl * 1000;
    const now = Date.now();
    const delay = expiresAt - now;
    if (delay <= 0) return;
    const timer = setTimeout(() => {
      messages = messages.filter(m => m.id !== message.id);
    }, delay);
    burnTimers.push(timer);
  }

  function clearBurnTimers() {
    for (const t of burnTimers) clearTimeout(t);
    burnTimers = [];
  }

  // Generate random per-session display name (adjective-animal)
  function generateDisplayName() {
    const adjectives = ['swift','calm','bright','quiet','bold','wild','cool','keen','warm','deep','free','safe','wise','brave','sharp','fresh','pale','dark','soft','loud'];
    const animals = ['fox','owl','wolf','bear','hawk','lynx','orca','crow','hare','moth','deer','wren','toad','seal','mink','crane','robin','dove','bass','ray'];
    const a = adjectives[Math.floor(Math.random() * adjectives.length)];
    const b = animals[Math.floor(Math.random() * animals.length)];
    return a + '-' + b;
  }

  function formatTime(isoString) {
    return new Date(isoString).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  // Extract code + key once on mount (not reactively — avoids re-run loops)
  onMount(() => {
    const hash = window.location.hash;
    roomCode = $page.params.code;
    if (hash && hash.startsWith('#key=')) {
      roomKey = hash.substring(5);
    } else {
      keyError = 'No encryption key found in URL. You must use a share link that contains #key=... to join a room.';
    }

    displayName = generateDisplayName();
    window.addEventListener('keydown', handleKeyDown);

    try {
      const token = sessionStorage.getItem('bb_creator_token_' + roomCode);
      if (token) {
        isCreator = true;
      }
    } catch (e) {}
  });

  onDestroy(() => {
    if (ws) ws.close();
    clearBurnTimers();
    window.removeEventListener('keydown', handleKeyDown);
    if (typingInputTimeout) clearTimeout(typingInputTimeout);
  });

  $effect(() => {
    return () => {
      if (ws) ws.close();
      clearBurnTimers();
    };
  });

  function handleKeyDown(e) {
    if (e.key === 'Escape') {
      handleQuickExit();
    }
  }

  function handleQuickExit() {
    window.location.replace('https://www.weather.com');
  }

  async function connectWS() {
    if (!roomKey || !roomCode) return;
    clearBurnTimers();

    let wsURL = `${WS_URL}/api/v1/rooms/${roomCode}/ws`;
    if (roomPassword) {
      wsURL += '?password=' + encodeURIComponent(roomPassword);
    }

    ws = new WebSocket(wsURL);

    ws.onopen = () => {
      connected = true;
      error = '';
      passwordPrompt = false;
    };

    ws.onmessage = async (event) => {
      try {
        const msg = JSON.parse(event.data);

        if (msg.type === 'room_destroyed') {
          try {
            sessionStorage.removeItem('bb_creator_token_' + roomCode);
          } catch (e) {}
          alert('This room has been destroyed.');
          window.location.replace('/');
          return;
        }

        if (msg.type === 'error') {
          if (msg.payload === 'Password required') {
            passwordPrompt = true;
            connected = false;
          } else if (msg.payload === 'Invalid password') {
            error = 'Wrong password. Try again.';
            passwordPrompt = true;
            connected = false;
          } else {
            error = msg.payload;
          }
          return;
        }

        if (msg.type === 'system' && msg.sender_tag && !senderTag) {
          senderTag = msg.sender_tag;
          return;
        }

        // Feature 2: participant count
        if (msg.type === 'participant_count') {
          participantCount = msg.count || 0;
          participantMax = msg.max || 10;
          participantText = msg.participant_text || `${participantCount} of ${participantMax} slots`;
          return;
        }

        // Feature 3: typing indicator
        if (msg.type === 'typing') {
          if (msg.sender_tag === senderTag) return; // skip own typing
          const name = msg.display_name || msg.sender_tag;
          typingUsers.set(name, Date.now());
          typingUsers = new Map(typingUsers); // trigger reactivity
          setTimeout(() => {
            typingUsers.delete(name);
            typingUsers = new Map(typingUsers);
          }, 3000);
          return;
        }

        // Feature 4: reactions
        if (msg.type === 'reaction') {
          try {
            const emoji = await decryptRoomReaction(msg.payload, msg.meta, roomKey);
            const targetId = msg.message_id;
            messages = messages.map(m => {
              if (m.id === targetId) {
                const reactions = m.reactions || [];
                // Avoid duplicate from same sender for same emoji
                const existing = reactions.find(r => r.sender === msg.sender_tag && r.emoji === emoji);
                if (!existing) {
                  reactions.push({
                    id: msg.reaction_id || crypto.randomUUID(),
                    sender: msg.sender_tag,
                    emoji: emoji,
                    createdAt: msg.created_at || new Date().toISOString(),
                  });
                }
                return { ...m, reactions };
              }
              return m;
            });
          } catch {
            // Decryption failed — ignore
          }
          return;
        }

        // Feature 5: revival proposal/result
        if (msg.type === 'revival_proposal') {
          revivalProposal = {
            proposalId: msg.proposal_id,
            proposedBy: msg.proposed_by,
            confirmations: msg.confirmations || 0,
            required: msg.required || 1,
            total: msg.total || 1,
          };
          return;
        }
        if (msg.type === 'revival_result') {
          revivalProposal = null;
          if (msg.accepted) {
            // Show system message about successful revival
            messages = [...messages, {
              id: 'system-revival-' + Date.now(),
              sender: 'System',
              text: `Room expiry extended to ${new Date(msg.new_expires).toLocaleString()} (${msg.confirmations} confirmed)`,
              ttl: 0,
              createdAt: new Date().toISOString(),
              decrypted: true,
              self: false,
            }];
          }
          return;
        }

        if (msg.type === 'message') {
          // Skip our own messages — they were already added locally in sendMessage
          if (msg.sender_tag === senderTag) return;

          try {
            const parsedMeta = msg.meta ? JSON.parse(msg.meta) : null;
            const plaintext = await decryptRoomMessage(
              msg.payload,
              parsedMeta?.nonce || msg.meta,
              roomKey
            );

            const newMsg = {
              id: msg.message_id || crypto.randomUUID(),
              sender: msg.sender_tag,
              text: plaintext,
              ttl: msg.ttl || 0,
              createdAt: msg.createdAt || new Date().toISOString(),
              decrypted: true,
              reactions: [],
            };
            messages = [...messages, newMsg];
            scheduleBurn(newMsg);
          } catch {
            const newMsg = {
              id: msg.message_id || crypto.randomUUID(),
              sender: msg.sender_tag,
              text: '[Decryption failed — wrong key or corrupted data]',
              ttl: msg.ttl || 0,
              createdAt: msg.createdAt || new Date().toISOString(),
              decrypted: false,
              reactions: [],
            };
            messages = [...messages, newMsg];
          }

          if (chatEl) {
            setTimeout(() => { chatEl.scrollTop = chatEl.scrollHeight; }, 50);
          }
        }

        // File attachment notification
        if (msg.type === 'file') {
          const newMsg = {
            id: msg.file_id || crypto.randomUUID(),
            sender: msg.sender_tag,
            text: null,
            file: {
              id: msg.file_id,
              name: msg.original_name,
              mimeType: msg.mime_type,
              size: msg.file_size,
              meta: msg.meta,
              encrypted: true,
            },
            ttl: msg.ttl || 0,
            createdAt: msg.created_at || new Date().toISOString(),
            decrypted: true,
            self: false,
            reactions: [],
          };
          messages = [...messages, newMsg];
          scheduleBurn(newMsg);
          if (chatEl) {
            setTimeout(() => { chatEl.scrollTop = chatEl.scrollHeight; }, 50);
          }
        }
      } catch {
        // Ignore malformed messages
      }
    };

    ws.onclose = () => {
      connected = false;
    };

    ws.onerror = () => {
      error = 'Connection lost.';
      connected = false;
    };
  }

  async function sendMessage(e) {
    e.preventDefault();
    if (!inputText.trim() || !ws || ws.readyState !== WebSocket.OPEN) return;

    try {
      const { ciphertext, nonce } = await encryptRoomMessage(inputText, roomKey);
      const now = new Date().toISOString();

      const payload = {
        type: 'message',
        payload: ciphertext,
        meta: JSON.stringify({ nonce }),
        ttl: selfDestruct,
      };

      ws.send(JSON.stringify(payload));

      // Show locally immediately (the broadcast echo will be skipped in onmessage)
      const localMsg = {
        id: 'pending-' + crypto.randomUUID(),
        sender: senderTag,
        text: inputText,
        ttl: selfDestruct,
        createdAt: now,
        decrypted: true,
        self: true,
        reactions: [],
      };
      messages = [...messages, localMsg];
      scheduleBurn(localMsg);

      inputText = '';

      if (chatEl) {
        setTimeout(() => { chatEl.scrollTop = chatEl.scrollHeight; }, 50);
      }
    } catch {
      error = 'Failed to encrypt message.';
    }
  }

  // Feature 3: send typing indicator on input
  function handleInput(e) {
    inputText = e.target.value;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'typing', display_name: displayName }));
    }
  }

  // Feature 4: send reaction to a message
  async function sendReaction(messageId, emoji) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try {
      const { ciphertext, nonce } = await encryptRoomReaction(emoji, roomKey);
      ws.send(JSON.stringify({
        type: 'reaction',
        message_id: messageId,
        payload: ciphertext,
        meta: JSON.stringify({ nonce }),
      }));
      // Add locally immediately
      messages = messages.map(m => {
        if (m.id === messageId) {
          const reactions = m.reactions || [];
          const existing = reactions.find(r => r.sender === senderTag && r.emoji === emoji);
          if (!existing) {
            reactions.push({
              id: 'pending-' + crypto.randomUUID(),
              sender: senderTag,
              emoji,
              createdAt: new Date().toISOString(),
            });
          }
          return { ...m, reactions };
        }
        return m;
      });
      emojiPickerMsgId = null;
    } catch {
      error = 'Failed to send reaction.';
    }
  }

  // Feature 5: propose room revival
  function proposeRevival() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ type: 'propose_revival' }));
  }

  function confirmRevival(proposalId) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ type: 'confirm_revival', proposal_id: proposalId }));
  }

  function rejectRevival(proposalId) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ type: 'reject_revival', proposal_id: proposalId }));
  }

  // Feature 1: file upload
  async function handleFileUpload(e) {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    uploading = true;

    for (const file of files) {
      if (file.size > 10 * 1024 * 1024) {
        error = `File "${file.name}" is too large (max 10 MB).`;
        continue;
      }
      try {
        const arrayBuffer = await file.arrayBuffer();
        const { ciphertext, nonce } = await encryptRoomFile(arrayBuffer, roomKey);
        const meta = JSON.stringify({ nonce });

        const formData = new FormData();
        // Convert base64 ciphertext to blob for upload
        const s = await import('libsodium-wrappers');
        await s.default.ready;
        const raw = s.default.from_base64(ciphertext, s.default.base64_variants.ORIGINAL);
        const blob = new Blob([raw]);
        formData.append('file', blob, file.name);
        formData.append('sender_tag', senderTag);
        formData.append('encryption_meta', meta);

        const resp = await fetch(`${API_URL}/api/v1/rooms/${roomCode}/files`, {
          method: 'POST',
          body: formData,
        });

        if (!resp.ok) {
          const d = await resp.json();
          error = d.error || 'File upload failed';
          continue;
        }

        const result = await resp.json();

        // Broadcast file attachment notification to all clients via WS
        ws.send(JSON.stringify({
          type: 'file',
          file_id: result.file_id,
          original_name: result.original_name,
          mime_type: result.mime_type,
          file_size: result.file_size,
          meta: meta,
        }));

        // Show locally
        const localFileMsg = {
          id: 'file-' + result.file_id,
          sender: senderTag,
          text: null,
          file: {
            id: result.file_id,
            name: result.original_name,
            mimeType: result.mime_type,
            size: result.file_size,
            meta,
            encrypted: true,
          },
          ttl: 0,
          createdAt: result.created_at,
          decrypted: true,
          self: true,
          reactions: [],
        };
        messages = [...messages, localFileMsg];
        if (chatEl) {
          setTimeout(() => { chatEl.scrollTop = chatEl.scrollHeight; }, 50);
        }
      } catch {
        error = 'Failed to upload file.';
      }
    }

    uploading = false;
    if (fileInput) fileInput.value = '';
  }

  // Feature 1: download and decrypt a room file
  async function downloadRoomFile(file) {
    try {
      const resp = await fetch(`${API_URL}/api/v1/rooms/${roomCode}/files/${file.id}`);
      if (!resp.ok) {
        error = 'Failed to download file.';
        return;
      }
      const metaHeader = resp.headers.get('X-File-Meta');
      const encryptedBlob = await resp.blob();

      // Decrypt with room key
      const rawArrayBuffer = await encryptedBlob.arrayBuffer();
      const s = await import('libsodium-wrappers');
      await s.default.ready;

      // The uploaded blob is the raw encrypted data; re-encrypt to get ciphertext
      // Actually the server stores the raw encrypted bytes, so we need to decrypt directly
      // using the nonce from the meta
      const meta = file.meta ? JSON.parse(file.meta) : null;
      const nonce = meta?.nonce;
      if (!nonce) {
        error = 'Missing encryption metadata.';
        return;
      }

      const decryptedBuffer = await decryptRoomFile(
        s.default.to_base64(new Uint8Array(rawArrayBuffer), s.default.base64_variants.ORIGINAL),
        nonce,
        roomKey
      );

      const blob = new Blob([decryptedBuffer]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      error = 'Failed to decrypt file. Wrong key?';
    }
  }
</script>

<svelte:head>
  <title>Secure Room - BurnerBox</title>
</svelte:head>

<div class="room-container min-h-screen bg-slate-900 flex flex-col">

  {#if keyError}
    <!-- No key — can't join -->
    <div class="flex-1 flex items-center justify-center p-4">
      <div class="bg-slate-800 rounded-lg p-8 shadow-xl max-w-md w-full text-center">
        <h1 class="text-2xl font-bold text-red-500 mb-4">Cannot Join Room</h1>
        <p class="text-slate-400 text-sm mb-6">{keyError}</p>
        <a href="/" class="bg-slate-700 hover:bg-slate-600 text-white px-6 py-3 rounded-lg inline-block no-underline">
          Go Home
        </a>
      </div>
    </div>

  {:else if passwordPrompt && !connected}
    <!-- Password required -->
    <div class="flex-1 flex items-center justify-center p-4">
      <div class="bg-slate-800 rounded-lg p-8 shadow-xl max-w-md w-full">
        <h1 class="text-2xl font-bold text-white mb-2 text-center">🔒 Room Password</h1>
        <p class="text-slate-400 text-sm text-center mb-6">
          This room is password protected.
        </p>

        {#if error}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{error}</p>
          </div>
        {/if}

        <form onsubmit={(e) => { e.preventDefault(); error = ''; connectWS(); }}>
          <input
            type="password"
            bind:value={roomPassword}
            placeholder="Enter room password"
            class="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 mb-4"
          />
          <button
            type="submit"
            disabled={!roomPassword}
            class="w-full bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white py-3 rounded-lg font-medium transition cursor-pointer"
          >
            Join Room
          </button>
        </form>
      </div>
    </div>

  {:else if !connected}
    <!-- Pre-connect screen -->
    <div class="flex-1 flex items-center justify-center p-4">
      <div class="bg-slate-800 rounded-lg p-8 shadow-xl max-w-md w-full text-center">
        <h1 class="text-2xl font-bold text-white mb-2">💬 Secure Room</h1>
        <p class="text-slate-400 text-sm mb-4">
          Room: <span class="font-mono text-emerald-400">{roomCode}</span>
        </p>
        <p class="text-slate-500 text-xs mb-6">
          End-to-end encrypted. The server never sees your plaintext.
        </p>

        {#if error}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{error}</p>
          </div>
        {/if}

        <button
          onclick={connectWS}
          class="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-3 rounded-lg font-medium transition cursor-pointer"
        >
          Connect to Room
        </button>

        <a href="/" class="block mt-4 text-slate-500 hover:text-white text-sm no-underline">
          ← Back
        </a>
      </div>
    </div>

  {:else}
    <!-- Connected: Chat Interface -->

    <!-- Header -->
    <div class="bg-slate-800 border-b border-slate-700 px-4 py-3 flex items-center justify-between shrink-0">
      <div class="flex items-center gap-3">
        <div>
          <h2 class="text-white font-bold text-sm">
            Room <span class="font-mono text-emerald-400">{roomCode}</span>
          </h2>
          <p class="text-slate-500 text-xs">
            You are: <span class="text-slate-300">{senderTag}</span>
            {#if connected}
              <span class="text-emerald-500">● connected</span>
            {:else}
              <span class="text-red-500">● disconnected</span>
            {/if}
            <span class="text-slate-400 ml-2">· {participantText}</span>
          </p>
        </div>
        <div class="bg-yellow-900/40 border border-yellow-700 rounded px-2 py-1">
          <p class="text-yellow-500 text-[10px] leading-tight text-center">
            Screenshots may be taken outside this browser.<br/>This is a deterrent, not a guarantee.
          </p>
        </div>
      </div>
      <div class="flex items-center gap-2">
        {#if isCreator}
          <button
            onclick={handleBurnRoom}
            disabled={burningRoom}
            class="bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-700/80 px-3 py-1.5 rounded font-bold text-xs transition cursor-pointer"
            title="Burn Room (Permanently Delete)"
          >
            {burningRoom ? 'Burning...' : '🔥 Burn Room'}
          </button>
        {/if}
        <button
          onclick={handleQuickExit}
          class="bg-red-600 hover:bg-red-700 text-white px-3 py-1.5 rounded font-bold text-xs transition cursor-pointer"
          title="Quick Exit (Esc)"
        >
          ⚡ EXIT <span class="text-red-300 text-[10px] font-normal">[Esc]</span>
        </button>
        <button
          onclick={() => { ws?.close(); connected = false; messages = []; clearBurnTimers(); participantCount = 0; }}
          class="text-slate-500 hover:text-white text-sm px-3 py-1 rounded bg-slate-700 cursor-pointer"
        >
          Leave
        </button>
      </div>
    </div>

    <!-- Feature 5: Room revival banner -->
    {#if revivalProposal}
      <div class="bg-amber-900/50 border border-amber-600 px-4 py-2 shrink-0 flex items-center justify-between">
        <div class="flex items-center gap-2">
          <span class="text-amber-400 text-sm font-medium">⏰ Revival Proposal</span>
          <span class="text-amber-300 text-xs">
            {revivalProposal.proposedBy} wants to extend expiry — {revivalProposal.confirmations}/{revivalProposal.required} confirmed
          </span>
        </div>
        <div class="flex gap-2">
          <button onclick={() => confirmRevival(revivalProposal.proposalId)}
            class="bg-emerald-600 hover:bg-emerald-700 text-white text-xs px-3 py-1 rounded cursor-pointer">
            ✓ Confirm
          </button>
          <button onclick={() => rejectRevival(revivalProposal.proposalId)}
            class="bg-slate-600 hover:bg-slate-500 text-white text-xs px-3 py-1 rounded cursor-pointer">
            ✕ Reject
          </button>
        </div>
      </div>
    {/if}

    <!-- Messages -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div
      bind:this={chatEl}
      class="flex-1 overflow-y-auto px-4 py-4 space-y-3 no-select"
    >
      {#if messages.length === 0}
        <div class="text-center py-12">
          <p class="text-slate-600 text-sm">No messages yet. Start the conversation.</p>
        </div>
      {/if}

      {#each messages as msg (msg.id)}
        <div class="flex flex-col {msg.self ? 'items-end' : 'items-start'}">
          <span class="text-slate-600 text-[10px] mb-1 px-1">
            {msg.sender} · {formatTime(msg.createdAt)}
            {#if msg.ttl > 0}
              · 💣 {msg.ttl}s burn
            {/if}
          </span>

          {#if msg.file}
            <!-- File attachment -->
            <div class="max-w-[75%] px-4 py-3 rounded-2xl bg-slate-700 text-white rounded-bl-md">
              <div class="flex items-center gap-3">
                <span class="text-2xl">📄</span>
                <div class="flex-1 min-w-0">
                  <p class="text-sm font-medium truncate">{msg.file.name}</p>
                  <p class="text-xs text-slate-400">{msg.file.mimeType} · {formatFileSize(msg.file.size)}</p>
                </div>
                <button onclick={() => downloadRoomFile(msg.file)}
                  class="bg-emerald-600 hover:bg-emerald-700 text-white text-xs px-3 py-1.5 rounded cursor-pointer shrink-0">
                  ↓ Decrypt & Save
                </button>
              </div>
            </div>
          {:else}
            <!-- Text message bubble -->
            <div
              class="max-w-[75%] px-4 py-2.5 rounded-2xl text-sm leading-relaxed relative
                {msg.self
                  ? 'bg-emerald-600 text-white rounded-br-md'
                  : 'bg-slate-700 text-white rounded-bl-md'}
                {!msg.decrypted ? 'bg-red-900/60 text-red-300 italic' : ''}"
            >
              <span class="message-text">{msg.text}</span>

              <!-- Reaction toggle button (on hover) -->
              {#if msg.decrypted && msg.id && !String(msg.id).startsWith('pending-') && !String(msg.id).startsWith('system-')}
                <button
                  onclick={() => { emojiPickerMsgId = emojiPickerMsgId === msg.id ? null : msg.id; }}
                  class="absolute -bottom-1 -right-1 text-xs opacity-0 group-hover:opacity-100 bg-slate-600 hover:bg-slate-500 rounded-full w-6 h-6 flex items-center justify-center cursor-pointer transition-opacity"
                  style="opacity: {emojiPickerMsgId === msg.id ? 1 : 0}"
                  onmouseenter={(e) => { e.target.style.opacity = 1; }}
                  onmouseleave={(e) => { if (emojiPickerMsgId !== msg.id) e.target.style.opacity = 0; }}
                >
                  😊
                </button>
              {/if}
            </div>
          {/if}

          <!-- Feature 4: Emoji reactions display -->
          {#if msg.reactions && msg.reactions.length > 0}
            <div class="flex flex-wrap gap-1 mt-1 px-1">
              {#each msg.reactions as reaction}
                <span class="bg-slate-700 border border-slate-600 rounded-full px-2 py-0.5 text-xs text-white">
                  {reaction.emoji}
                </span>
              {/each}
            </div>
          {/if}

          <!-- Feature 4: Emoji picker popup -->
          {#if emojiPickerMsgId === msg.id}
            <div class="bg-slate-800 border border-slate-600 rounded-lg p-2 flex gap-1 mt-1 shadow-lg">
              {#each reactionEmojis as emoji}
                <button
                  onclick={() => sendReaction(msg.id, emoji)}
                  class="hover:bg-slate-700 rounded px-1.5 py-1 text-lg cursor-pointer transition"
                >
                  {emoji}
                </button>
              {/each}
            </div>
          {/if}
        </div>
      {/each}

      <!-- Feature 3: Typing indicator -->
      {#if typingUsers.size > 0}
        <div class="text-slate-500 text-xs px-2 italic">
          {#each [...typingUsers.keys()] as name, i}{#if i > 0}, {/if}{name}{/each}
          {typingUsers.size === 1 ? 'is' : 'are'} typing…
        </div>
      {/if}
    </div>

    <!-- Input Bar — mobile: stacked for thumb reach; desktop: inline -->
    <div class="bg-slate-800 border-t border-slate-700 px-4 py-3 shrink-0 safe-bottom">
      {#if error}
        <p class="text-red-400 text-xs mb-2">{error}</p>
      {/if}
      <form onsubmit={sendMessage}>
        <!-- Message input + send row -->
        <div class="flex gap-2 items-end mb-2">
          <input
            type="text"
            value={inputText}
            oninput={handleInput}
            placeholder="Type an encrypted message..."
            maxlength="50000"
            class="flex-1 px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 min-w-0"
          />
          <button
            type="submit"
            disabled={!inputText.trim()}
            class="bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white px-5 py-3 rounded-lg font-medium transition cursor-pointer shrink-0"
          >
            Send
          </button>
        </div>
        <!-- Actions row — always visible, thumb-reachable -->
        <div class="flex gap-2 items-center flex-wrap">
          <select
            bind:value={selfDestruct}
            class="flex-1 min-w-[120px] px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-slate-300 text-xs cursor-pointer focus:outline-none"
          >
            {#each burnOptions as opt}
              <option value={opt.value}>💣 {opt.label}</option>
            {/each}
          </select>
          <input type="file" bind:this={fileInput} onchange={handleFileUpload}
            class="hidden" multiple accept="*/*" />
          <button type="button" onclick={() => fileInput?.click()}
            disabled={uploading}
            class="bg-slate-700 hover:bg-slate-600 disabled:bg-slate-800 text-white px-3 py-2 rounded-lg transition cursor-pointer shrink-0 text-lg"
            title="Attach encrypted file">
            📎
          </button>
          <button type="button" onclick={proposeRevival}
            class="bg-amber-700 hover:bg-amber-600 text-white px-3 py-2 rounded-lg transition cursor-pointer shrink-0 text-lg"
            title="Propose extending room expiry">
            ⏰
          </button>
        </div>
      </form>
    </div>
  {/if}
</div>

<style>
  /* Anti-screenshot friction: disable text selection on message text */
  .no-select {
    -webkit-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
    user-select: none;
  }
  .message-text {
    -webkit-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
    user-select: none;
  }

  /* Ensure chat fills viewport */
  .room-container {
    height: 100vh;
    height: 100dvh;
  }

  /* Safe area for mobile notch/rounded corners */
  .safe-bottom {
    padding-bottom: max(0.75rem, env(safe-area-inset-bottom));
  }
</style>
