<script>
  import { generateKeyPair, encryptPrivateKey, cacheDerivedKey, validatePGPPublicKey } from '$lib/crypto';
  import { API_URL } from '$lib/api';
  import { t } from '$lib/i18n';

  // Svelte 5 Runes
  let name = $state('');
  let email = $state('');
  let password = $state('');
  let confirmPassword = $state('');
  let encryptionScheme = $state('libsodium'); // 'libsodium' | 'pgp'
  let pgpPublicKey = $state('');
  let pgpKeyValidation = $state(null);
  let error = $state('');
  let loading = $state(false);
  let success = $state(false);
  let submissionUrl = $state('');
  let countdown = $state(5);
  let redirectTimer = null;
  let generatingKeys = $state(false);

  // Svelte 5 cleanup using $effect
  $effect(() => {
    return () => {
      if (redirectTimer) {
        clearInterval(redirectTimer);
      }
    };
  });

  async function handlePGPKeyChange() {
    if (!pgpPublicKey.trim()) {
      pgpKeyValidation = null;
      return;
    }
    const res = await validatePGPPublicKey(pgpPublicKey);
    pgpKeyValidation = res;
  }

  function startRedirectCountdown() {
    redirectTimer = setInterval(() => {
      countdown -= 1;
      if (countdown <= 0) {
        clearInterval(redirectTimer);
        window.location.href = '/login';
      }
    }, 1000);
  }

  async function handleSignup(e) {
    if (e) e.preventDefault();
    error = '';

    if (password !== confirmPassword) {
      error = $t('signup.error_passwords_match');
      return;
    }
    if (password.length < 8) {
      error = $t('signup.error_password_length');
      return;
    }

    loading = true;

    try {
      let finalPublicKey = '';

      if (encryptionScheme === 'pgp') {
        if (!pgpPublicKey.trim()) {
          error = 'Please paste your ASCII-armored PGP public key.';
          loading = false;
          return;
        }
        const validation = await validatePGPPublicKey(pgpPublicKey);
        if (!validation.valid) {
          error = 'Invalid PGP public key format: ' + (validation.error || 'Must be ASCII-armored block');
          loading = false;
          return;
        }
        finalPublicKey = pgpPublicKey.trim();
        // PGP private keys are held outside BurnerBox entirely — ensure no localStorage storage
        localStorage.removeItem('burnerbox_private_key');
      } else {
        // libsodium flow
        generatingKeys = true;
        const keyPair = await generateKeyPair();
        finalPublicKey = keyPair.publicKey;

        const encResult = await encryptPrivateKey(keyPair.privateKey, password);
        localStorage.setItem('burnerbox_private_key', JSON.stringify({
          encrypted: encResult.encryptedPrivateKey,
          salt: encResult.salt,
          nonce: encResult.nonce,
        }));

        const derivedKey = await (await import('$lib/crypto')).deriveKeyFromPassword(
          password, encResult.salt
        );
        cacheDerivedKey(derivedKey);
      }

      const response = await fetch(`${API_URL}/api/v1/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          email,
          password,
          public_key: finalPublicKey,
          encryption_scheme: encryptionScheme,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        if (encryptionScheme === 'libsodium') {
          localStorage.removeItem('burnerbox_private_key');
        }
        error = data.error || $t('signup.error_failed');
        loading = false;
        generatingKeys = false;
        return;
      }

      const slug = data.organization.submission_slug;
      submissionUrl = `${window.location.origin}/submit/${slug}`;
      success = true;
      startRedirectCountdown();

    } catch (err) {
      if (encryptionScheme === 'libsodium') {
        localStorage.removeItem('burnerbox_private_key');
      }
      error = $t('signup.error_network') + ': ' + err.message;
    }

    loading = false;
    generatingKeys = false;
  }
</script>

<div class="min-h-screen flex items-center justify-center p-4">
  <div class="bg-slate-800 rounded-lg p-8 max-w-lg w-full shadow-xl">
    
    <div class="text-center mb-6">
      <h1 class="text-3xl font-bold text-emerald-500">🔥 BurnerBox</h1>
      <p class="text-slate-400 mt-2">{$t('signup.title')}</p>
    </div>

    {#if success}
      <div class="bg-emerald-900/50 border border-emerald-500 rounded-lg p-4">
        <p class="text-emerald-400 text-lg font-bold mb-2">{$t('signup.success_title')}</p>
        <p class="text-slate-300 text-sm mb-4">
          {$t('signup.secret_url_hint')}
        </p>
        <div class="bg-slate-900 rounded p-3 mb-4">
          <code class="text-emerald-400 text-sm break-all">{submissionUrl}</code>
        </div>
        <button
          onclick={() => {
            navigator.clipboard.writeText(submissionUrl);
          }}
          class="w-full bg-slate-700 hover:bg-slate-600 text-white py-2 rounded-lg text-sm transition mb-3 cursor-pointer"
        >
          {$t('signup.copy_url')}
        </button>
        
        <div class="bg-slate-700 rounded p-2 mb-3 text-center">
          <p class="text-slate-300 text-xs">
            {$t('signup.redirect_countdown')} <span class="text-emerald-400 font-bold">{countdown}</span> {$t('signup.seconds')}
          </p>
        </div>

        {#if encryptionScheme === 'libsodium'}
          <div class="bg-yellow-900/50 border border-yellow-500 rounded p-2 mb-3">
            <p class="text-yellow-400 text-xs">
              {$t('signup.key_warning')}
            </p>
          </div>
        {:else}
          <div class="bg-blue-900/50 border border-blue-500 rounded p-2 mb-3">
            <p class="text-blue-300 text-xs">
              🛡️ <strong>PGP Configured:</strong> Your PGP private key remains safely on your device. You will import it in-memory whenever decrypting tips in the dashboard.
            </p>
          </div>
        {/if}

        <a
          href="/login"
          class="block w-full text-center bg-emerald-600 hover:bg-emerald-700 text-white py-2 rounded-lg font-medium transition no-underline"
        >
          {$t('signup.go_to_login')}
        </a>
      </div>
    {:else}
      <form onsubmit={handleSignup}>
        
        {#if error}
          <div class="bg-red-900/50 border border-red-500 rounded-lg p-3 mb-4">
            <p class="text-red-400 text-sm">{error}</p>
          </div>
        {/if}

        <div class="mb-4">
          <label for="name" class="block text-sm font-medium text-slate-300 mb-1">
            {$t('signup.org_name')}
          </label>
          <input
            id="name"
            type="text"
            bind:value={name}
            required
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            placeholder={$t('signup.org_name_placeholder')}
          />
        </div>

        <div class="mb-4">
          <label for="email" class="block text-sm font-medium text-slate-300 mb-1">
            {$t('auth.email')}
          </label>
          <input
            id="email"
            type="email"
            bind:value={email}
            required
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            placeholder={$t('signup.email_placeholder')}
          />
        </div>

        <div class="mb-4">
          <label for="password" class="block text-sm font-medium text-slate-300 mb-1">
            {$t('auth.password')}
          </label>
          <input
            id="password"
            type="password"
            bind:value={password}
            required
            minlength="8"
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            placeholder={$t('signup.password_placeholder')}
          />
        </div>

        <div class="mb-4">
          <label for="confirmPassword" class="block text-sm font-medium text-slate-300 mb-1">
            {$t('signup.confirm_password')}
          </label>
          <input
            id="confirmPassword"
            type="password"
            bind:value={confirmPassword}
            required
            minlength="8"
            class="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            placeholder={$t('signup.confirm_placeholder')}
          />
        </div>

        <!-- Encryption Scheme Selection -->
        <div class="mb-5 bg-slate-900/60 border border-slate-700 rounded-lg p-4">
          <div class="block text-sm font-bold text-white mb-2">
            🔐 Encryption Scheme
          </div>
          
          <div class="grid grid-cols-2 gap-3 mb-3">
            <button
              type="button"
              onclick={() => { encryptionScheme = 'libsodium'; }}
              class="p-3 rounded-lg border text-left transition cursor-pointer {encryptionScheme === 'libsodium' ? 'bg-emerald-950/60 border-emerald-500 text-white ring-1 ring-emerald-500' : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'}"
            >
              <div class="font-bold text-sm flex items-center gap-1.5 mb-1 text-emerald-400">
                <span>⚡ libsodium</span>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed">
                Generate new in-browser keypair. Automatic & zero-friction.
              </p>
            </button>

            <button
              type="button"
              onclick={() => { encryptionScheme = 'pgp'; }}
              class="p-3 rounded-lg border text-left transition cursor-pointer {encryptionScheme === 'pgp' ? 'bg-blue-950/60 border-blue-500 text-white ring-1 ring-blue-500' : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'}"
            >
              <div class="font-bold text-sm flex items-center gap-1.5 mb-1 text-blue-400">
                <span>🛡️ PGP / GPG</span>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed">
                Paste existing PGP key. Sovereign & interoperable.
              </p>
            </button>
          </div>

          <!-- Explainer Trade-offs -->
          <div class="text-xs text-slate-400 bg-slate-800/80 rounded p-2.5 border border-slate-700/60 mb-3">
            {#if encryptionScheme === 'libsodium'}
              <p>
                <strong>Trade-off:</strong> <span class="text-emerald-300 font-medium">Simpler & automated.</span> BurnerBox creates and secures your private key in your browser. Best for teams wanting zero-friction setup without managing raw PGP keyrings.
              </p>
            {:else}
              <p>
                <strong>Trade-off:</strong> <span class="text-blue-300 font-medium">Interoperable & sovereign.</span> Use your existing GPG keypair (Thunderbird, Mailvelope, YubiKey). Your private key stays on your local machine and is never stored in BurnerBox.
              </p>
            {/if}
          </div>

          <!-- PGP Public Key Input (if PGP selected) -->
          {#if encryptionScheme === 'pgp'}
            <div>
              <label for="pgpKey" class="block text-xs font-semibold text-slate-300 mb-1">
                Paste ASCII-Armored PGP Public Key:
              </label>
              <textarea
                id="pgpKey"
                bind:value={pgpPublicKey}
                oninput={handlePGPKeyChange}
                rows="5"
                placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;...&#10;-----END PGP PUBLIC KEY BLOCK-----"
                class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-emerald-400 font-mono text-xs placeholder-slate-600 focus:outline-none focus:border-blue-500 resize-none"
              ></textarea>
              {#if pgpKeyValidation}
                {#if pgpKeyValidation.valid}
                  <p class="text-xs text-emerald-400 mt-1 flex items-center gap-1">
                    ✅ Valid PGP Key (ID: {pgpKeyValidation.keyID?.substring(0, 8)})
                  </p>
                {:else}
                  <p class="text-xs text-red-400 mt-1">
                    ❌ Invalid: {pgpKeyValidation.error}
                  </p>
                {/if}
              {/if}
            </div>
          {/if}
        </div>

        <button
          type="submit"
          disabled={loading}
          class="w-full bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white py-2.5 rounded-lg font-medium transition cursor-pointer"
        >
          {#if loading}
            {generatingKeys ? $t('signup.generating_keys') : $t('signup.creating_account')}
          {:else}
            {$t('signup.register_btn')}
          {/if}
        </button>
      </form>

      <p class="text-center text-slate-400 text-sm mt-6">
        {$t('signup.already_registered')}
        <a href="/login" class="text-emerald-500 hover:underline ml-1">{$t('signup.login_link')}</a>
      </p>
    {/if}
  </div>
</div>