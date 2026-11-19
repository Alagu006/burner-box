import sodium from 'libsodium-wrappers';
import * as openpgp from 'openpgp';

// Initialize sodium
let sodiumReady = null;
async function getSodium() {
  if (!sodiumReady) {
    sodiumReady = sodium.ready;
  }
  await sodiumReady;
  return sodium;
}

// Generate a key pair for the organization (libsodium)
export async function generateKeyPair() {
  const s = await getSodium();
  const keyPair = s.crypto_box_keypair();
  return {
    publicKey: s.to_base64(keyPair.publicKey, s.base64_variants.ORIGINAL),
    privateKey: s.to_base64(keyPair.privateKey, s.base64_variants.ORIGINAL),
  };
}

// Encrypt a message for a recipient's public key (libsodium)
// Returns { ciphertext, nonce, encryptedKey, boxNonce, senderPublicKey }
export async function encryptForRecipient(message, recipientPublicKeyBase64) {
  const s = await getSodium();
  const recipientPublicKey = s.from_base64(recipientPublicKeyBase64, s.base64_variants.ORIGINAL);
  
  // Generate a random symmetric key (using crypto_secretbox)
  const symmetricKey = s.randombytes_buf(s.crypto_secretbox_KEYBYTES);
  
  // Encrypt message with symmetric key
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const ciphertext = s.crypto_secretbox_easy(message, nonce, symmetricKey);
  
  // Encrypt the symmetric key with recipient's public key (using crypto_box)
  const boxNonce = s.randombytes_buf(s.crypto_box_NONCEBYTES);
  const senderKeyPair = s.crypto_box_keypair(); // ephemeral sender
  const encryptedKey = s.crypto_box_easy(
    symmetricKey,
    boxNonce,
    recipientPublicKey,
    senderKeyPair.privateKey
  );
  
  return {
    ciphertext: s.to_base64(ciphertext, s.base64_variants.ORIGINAL),
    nonce: s.to_base64(nonce, s.base64_variants.ORIGINAL),
    encryptedKey: s.to_base64(encryptedKey, s.base64_variants.ORIGINAL),
    boxNonce: s.to_base64(boxNonce, s.base64_variants.ORIGINAL),
    senderPublicKey: s.to_base64(senderKeyPair.publicKey, s.base64_variants.ORIGINAL),
  };
}

// Decrypt a message using recipient's private key (libsodium)
export async function decryptFromSender(encryptedData, recipientPrivateKeyBase64) {
  const s = await getSodium();
  const recipientPrivateKey = s.from_base64(recipientPrivateKeyBase64, s.base64_variants.ORIGINAL);
  
  // Decrypt the symmetric key
  const senderPublicKey = s.from_base64(encryptedData.senderPublicKey, s.base64_variants.ORIGINAL);
  const boxNonce = s.from_base64(encryptedData.boxNonce, s.base64_variants.ORIGINAL);
  const encryptedKey = s.from_base64(encryptedData.encryptedKey, s.base64_variants.ORIGINAL);
  
  const symmetricKey = s.crypto_box_open_easy(
    encryptedKey,
    boxNonce,
    senderPublicKey,
    recipientPrivateKey
  );
  
  // Decrypt the message
  const nonce = s.from_base64(encryptedData.nonce, s.base64_variants.ORIGINAL);
  const ciphertext = s.from_base64(encryptedData.ciphertext, s.base64_variants.ORIGINAL);
  
  const plaintext = s.crypto_secretbox_open_easy(ciphertext, nonce, symmetricKey);
  
  return new TextDecoder().decode(plaintext);
}

// Encrypt a file (ArrayBuffer) for a recipient (libsodium)
export async function encryptFile(fileData, recipientPublicKeyBase64) {
  const s = await getSodium();
  const recipientPublicKey = s.from_base64(recipientPublicKeyBase64, s.base64_variants.ORIGINAL);
  
  // Generate symmetric key
  const symmetricKey = s.randombytes_buf(s.crypto_secretbox_KEYBYTES);
  
  // Encrypt file data
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const ciphertext = s.crypto_secretbox_easy(new Uint8Array(fileData), nonce, symmetricKey);
  
  // Encrypt symmetric key
  const boxNonce = s.randombytes_buf(s.crypto_box_NONCEBYTES);
  const senderKeyPair = s.crypto_box_keypair();
  const encryptedKey = s.crypto_box_easy(
    symmetricKey,
    boxNonce,
    recipientPublicKey,
    senderKeyPair.privateKey
  );
  
  return {
    ciphertext: s.to_base64(ciphertext, s.base64_variants.ORIGINAL),
    nonce: s.to_base64(nonce, s.base64_variants.ORIGINAL),
    encryptedKey: s.to_base64(encryptedKey, s.base64_variants.ORIGINAL),
    boxNonce: s.to_base64(boxNonce, s.base64_variants.ORIGINAL),
    senderPublicKey: s.to_base64(senderKeyPair.publicKey, s.base64_variants.ORIGINAL),
  };
}

// Decrypt a file (libsodium)
export async function decryptFile(encryptedData, recipientPrivateKeyBase64) {
  const s = await getSodium();
  const recipientPrivateKey = s.from_base64(recipientPrivateKeyBase64, s.base64_variants.ORIGINAL);
  
  const senderPublicKey = s.from_base64(encryptedData.senderPublicKey, s.base64_variants.ORIGINAL);
  const boxNonce = s.from_base64(encryptedData.boxNonce, s.base64_variants.ORIGINAL);
  const encryptedKey = s.from_base64(encryptedData.encryptedKey, s.base64_variants.ORIGINAL);
  
  const symmetricKey = s.crypto_box_open_easy(
    encryptedKey,
    boxNonce,
    senderPublicKey,
    recipientPrivateKey
  );
  
  const nonce = s.from_base64(encryptedData.nonce, s.base64_variants.ORIGINAL);
  const ciphertext = s.from_base64(encryptedData.ciphertext, s.base64_variants.ORIGINAL);
  
  const plaintext = s.crypto_secretbox_open_easy(ciphertext, nonce, symmetricKey);
  
  return plaintext.buffer;
}

// ==========================================
// ===== OPENPGP.JS INTEGRATION (PGP FLOW) =====
// ==========================================

// Validate ASCII-armored PGP public key
export async function validatePGPPublicKey(armoredKey) {
  try {
    const key = await openpgp.readKey({ armoredKey: armoredKey.trim() });
    return { valid: true, keyID: key.getKeyID().toHex(), fingerprint: key.getFingerprint() };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

// Generate a PGP key pair (used for tests and in-browser setup if needed)
export async function generatePGPKeyPair(name = 'BurnerBox User', email = 'user@burnerbox.local', passphrase = '') {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'rsa',
    rsaBits: 2048,
    userIDs: [{ name, email }],
    passphrase,
  });
  return { publicKey, privateKey };
}

// Encrypt text message with PGP public key (returns ASCII-armored string)
export async function encryptWithPGP(plaintext, armoredPublicKey) {
  const publicKey = await openpgp.readKey({ armoredKey: armoredPublicKey.trim() });
  const message = await openpgp.createMessage({ text: plaintext });
  const armoredCiphertext = await openpgp.encrypt({
    message,
    encryptionKeys: publicKey,
  });
  return armoredCiphertext;
}

// Decrypt PGP message with private key (and optional passphrase)
export async function decryptWithPGP(armoredCiphertext, armoredPrivateKey, passphrase = '') {
  let privateKey = await openpgp.readPrivateKey({ armoredKey: armoredPrivateKey.trim() });
  if (passphrase) {
    privateKey = await openpgp.decryptKey({
      privateKey,
      passphrase,
    });
  }
  const message = await openpgp.readMessage({ armoredMessage: armoredCiphertext.trim() });
  const { data: decrypted } = await openpgp.decrypt({
    message,
    decryptionKeys: privateKey,
  });
  return decrypted;
}

// Encrypt binary file data with PGP public key
export async function encryptFileWithPGP(fileData, armoredPublicKey) {
  const publicKey = await openpgp.readKey({ armoredKey: armoredPublicKey.trim() });
  const message = await openpgp.createMessage({ binary: new Uint8Array(fileData) });
  const armoredCiphertext = await openpgp.encrypt({
    message,
    encryptionKeys: publicKey,
    format: 'armored',
  });
  return armoredCiphertext;
}

// Decrypt binary file data with PGP private key
export async function decryptFileWithPGP(armoredCiphertext, armoredPrivateKey, passphrase = '') {
  let privateKey = await openpgp.readPrivateKey({ armoredKey: armoredPrivateKey.trim() });
  if (passphrase) {
    privateKey = await openpgp.decryptKey({
      privateKey,
      passphrase,
    });
  }
  const message = await openpgp.readMessage({ armoredMessage: armoredCiphertext.trim() });
  const { data: decrypted } = await openpgp.decrypt({
    message,
    decryptionKeys: privateKey,
    format: 'binary',
  });
  return decrypted.buffer.slice(decrypted.byteOffset, decrypted.byteOffset + decrypted.byteLength);
}

// ========================================================
// ===== TRANSIENT IN-MEMORY PGP PRIVATE KEY STORE ========
// Note: PGP private keys are NEVER persisted to localStorage
// ========================================================

let _transientPGPPrivateKey = null;
let _transientPGPPassphrase = '';

export function setTransientPGPPrivateKey(armoredKey, passphrase = '') {
  _transientPGPPrivateKey = armoredKey ? armoredKey.trim() : null;
  _transientPGPPassphrase = passphrase || '';
}

export function getTransientPGPPrivateKey() {
  if (!_transientPGPPrivateKey) return null;
  return {
    privateKey: _transientPGPPrivateKey,
    passphrase: _transientPGPPassphrase,
  };
}

export function clearTransientPGPPrivateKey() {
  _transientPGPPrivateKey = null;
  _transientPGPPassphrase = '';
}

// ========================================================
// ===== UNIFIED SUBMISSION ENCRYPTION & DECRYPTION =======
// ========================================================

// Encrypt submission text based on org's encryption scheme ('libsodium' | 'pgp')
export async function encryptSubmission(plaintext, orgPublicKey, scheme = 'libsodium') {
  if (scheme === 'pgp') {
    const ciphertext = await encryptWithPGP(plaintext, orgPublicKey);
    return {
      ciphertext,
      encryptionMeta: JSON.stringify({ scheme: 'pgp' }),
    };
  }

  // Default: libsodium flow
  const encResult = await encryptForRecipient(plaintext, orgPublicKey);
  const encryptionMeta = {
    scheme: 'libsodium',
    nonce: encResult.nonce,
    encryptedKey: encResult.encryptedKey,
    boxNonce: encResult.boxNonce,
    senderPublicKey: encResult.senderPublicKey,
  };
  return {
    ciphertext: encResult.ciphertext,
    encryptionMeta: JSON.stringify(encryptionMeta),
  };
}

// Decrypt submission text based on metadata / scheme
export async function decryptSubmission(ciphertext, metaJsonStr, key, scheme = 'libsodium', pgpPassphrase = '') {
  let meta = {};
  if (metaJsonStr) {
    try {
      meta = typeof metaJsonStr === 'string' ? JSON.parse(metaJsonStr) : metaJsonStr;
    } catch {
      // Fallback
    }
  }

  const effectiveScheme = meta.scheme || scheme || 'libsodium';

  if (effectiveScheme === 'pgp' || (typeof ciphertext === 'string' && ciphertext.includes('-----BEGIN PGP MESSAGE-----'))) {
    return await decryptWithPGP(ciphertext, key, pgpPassphrase);
  }

  // Libsodium flow
  return await decryptFromSender(
    {
      ciphertext,
      nonce: meta.nonce,
      encryptedKey: meta.encryptedKey,
      boxNonce: meta.boxNonce,
      senderPublicKey: meta.senderPublicKey,
    },
    key
  );
}

// ---- Key-at-rest encryption (Argon2id + AES for libsodium private keys) ----
let _cachedDerivedKey = null;

// Derive a 32-byte key from a password using cryptographic KDF.
// The salt is stored alongside the encrypted key.
export async function deriveKeyFromPassword(password, saltBase64) {
  const s = await getSodium();
  const salt = s.from_base64(saltBase64, s.base64_variants.ORIGINAL);
  const keyBytes = s.crypto_secretbox_KEYBYTES || 32;

  if (typeof s.crypto_pwhash === 'function') {
    const opsLimit = s.crypto_pwhash_OPSLIMIT_INTERACTIVE || 2;
    const memLimit = s.crypto_pwhash_MEMLIMIT_INTERACTIVE || 67108864;
    const alg = s.crypto_pwhash_ALG_ARGON2ID13 || 2;
    return s.crypto_pwhash(keyBytes, password, salt, opsLimit, memLimit, alg);
  }

  // BLAKE2b keyed hash KDF
  return s.crypto_generichash(keyBytes, password, salt);
}

// Cache a derived key in memory for the session (never persisted).
export function cacheDerivedKey(key) {
  _cachedDerivedKey = key;
}

// Retrieve the cached derived key (returns null if not cached).
export function getCachedDerivedKey() {
  return _cachedDerivedKey;
}

// Clear the cached derived key (on logout).
export function clearDerivedKey() {
  _cachedDerivedKey = null;
}

// Read the org private key from localStorage (libsodium only)
export async function getStoredPrivateKey() {
  const raw = localStorage.getItem('burnerbox_private_key');
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed.salt && parsed.nonce && parsed.encrypted) {
      // Encrypted format — need cached derived key
      const derivedKey = getCachedDerivedKey();
      if (!derivedKey) return null;
      const s = await getSodium();
      const ciphertext = s.from_base64(parsed.encrypted, s.base64_variants.ORIGINAL);
      const nonce = s.from_base64(parsed.nonce, s.base64_variants.ORIGINAL);
      const plaintext = s.crypto_secretbox_open_easy(ciphertext, nonce, derivedKey);
      return s.to_base64(plaintext, s.base64_variants.ORIGINAL);
    }
  } catch {
    // Not JSON — treat as legacy raw base64
  }
  return raw;
}

// Encrypt a private key for localStorage storage (libsodium only)
// Returns { encryptedPrivateKey, salt, nonce } (all base64).
export async function encryptPrivateKey(privateKeyBase64, password) {
  const s = await getSodium();
  const saltBytes = s.crypto_pwhash_SALTBYTES || 16;
  const nonceBytes = s.crypto_secretbox_NONCEBYTES || 24;
  const salt = s.randombytes_buf(saltBytes);
  const key = await deriveKeyFromPassword(password, s.to_base64(salt, s.base64_variants.ORIGINAL));
  const nonce = s.randombytes_buf(nonceBytes);
  const plaintext = s.from_base64(privateKeyBase64, s.base64_variants.ORIGINAL);
  const ciphertext = s.crypto_secretbox_easy(plaintext, nonce, key);
  return {
    encryptedPrivateKey: s.to_base64(ciphertext, s.base64_variants.ORIGINAL),
    salt: s.to_base64(salt, s.base64_variants.ORIGINAL),
    nonce: s.to_base64(nonce, s.base64_variants.ORIGINAL),
  };
}

// Decrypt a private key stored in localStorage (libsodium only)
// Returns the private key as a base64 string.
export async function decryptPrivateKey(encryptedB64, saltBase64, nonceBase64, password) {
  const s = await getSodium();
  const key = await deriveKeyFromPassword(password, saltBase64);
  const ciphertext = s.from_base64(encryptedB64, s.base64_variants.ORIGINAL);
  const nonce = s.from_base64(nonceBase64, s.base64_variants.ORIGINAL);
  const plaintext = s.crypto_secretbox_open_easy(ciphertext, nonce, key);
  return s.to_base64(plaintext, s.base64_variants.ORIGINAL);
}

// Generate a friendly, secure random passphrase for anonymous submitters
export function generatePassphrase() {
  const words = [
    'coral', 'haven', 'flame', 'river', 'ember', 'solar', 'frost', 'orbit',
    'cedar', 'delta', 'prism', 'vivid', 'swift', 'pulse', 'storm', 'crest',
    'shadow', 'beacon', 'valley', 'timber', 'shield', 'summit', 'aurora', 'matrix',
    'harbor', 'quartz', 'canyon', 'breeze', 'tundra', 'sentry', 'galaxy', 'meteor'
  ];
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const randArr = new Uint32Array(4);
    crypto.getRandomValues(randArr);
    const w1 = words[randArr[0] % words.length];
    const w2 = words[randArr[1] % words.length];
    const w3 = words[randArr[2] % words.length];
    const num = (randArr[3] % 9000) + 1000;
    return `${w1}-${w2}-${w3}-${num}`;
  }
  const r1 = words[Math.floor(Math.random() * words.length)];
  const r2 = words[Math.floor(Math.random() * words.length)];
  const r3 = words[Math.floor(Math.random() * words.length)];
  const num = Math.floor(1000 + Math.random() * 9000);
  return `${r1}-${r2}-${r3}-${num}`;
}

// ==========================================
// ===== EPHEMERAL ROOM CRYPTO HELPERS ======
// ==========================================

export async function generateRoomKey() {
  const s = await getSodium();
  const key = s.randombytes_buf(s.crypto_secretbox_KEYBYTES);
  return s.to_base64(key, s.base64_variants.ORIGINAL);
}

export async function deriveRoomKey(password, saltBase64) {
  return await deriveKeyFromPassword(password, saltBase64);
}

export async function encryptRoomMessage(message, roomKeyBase64) {
  const s = await getSodium();
  const key = typeof roomKeyBase64 === 'string' ? s.from_base64(roomKeyBase64, s.base64_variants.ORIGINAL) : roomKeyBase64;
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const ciphertext = s.crypto_secretbox_easy(message, nonce, key);
  return {
    ciphertext: s.to_base64(ciphertext, s.base64_variants.ORIGINAL),
    nonce: s.to_base64(nonce, s.base64_variants.ORIGINAL),
  };
}

export async function decryptRoomMessage(ciphertextB64, nonceB64, roomKeyBase64) {
  const s = await getSodium();
  const key = typeof roomKeyBase64 === 'string' ? s.from_base64(roomKeyBase64, s.base64_variants.ORIGINAL) : roomKeyBase64;
  const ciphertext = s.from_base64(ciphertextB64, s.base64_variants.ORIGINAL);
  const nonce = s.from_base64(nonceB64, s.base64_variants.ORIGINAL);
  const plaintext = s.crypto_secretbox_open_easy(ciphertext, nonce, key);
  return new TextDecoder().decode(plaintext);
}

export async function encryptRoomFile(fileData, roomKeyBase64) {
  const s = await getSodium();
  const key = typeof roomKeyBase64 === 'string' ? s.from_base64(roomKeyBase64, s.base64_variants.ORIGINAL) : roomKeyBase64;
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const ciphertext = s.crypto_secretbox_easy(new Uint8Array(fileData), nonce, key);
  return {
    ciphertext: s.to_base64(ciphertext, s.base64_variants.ORIGINAL),
    nonce: s.to_base64(nonce, s.base64_variants.ORIGINAL),
  };
}

export async function decryptRoomFile(ciphertextB64, nonceB64, roomKeyBase64) {
  const s = await getSodium();
  const key = typeof roomKeyBase64 === 'string' ? s.from_base64(roomKeyBase64, s.base64_variants.ORIGINAL) : roomKeyBase64;
  const ciphertext = s.from_base64(ciphertextB64, s.base64_variants.ORIGINAL);
  const nonce = s.from_base64(nonceB64, s.base64_variants.ORIGINAL);
  const plaintext = s.crypto_secretbox_open_easy(ciphertext, nonce, key);
  return plaintext.buffer;
}

export async function encryptRoomReaction(reaction, roomKeyBase64) {
  return await encryptRoomMessage(JSON.stringify(reaction), roomKeyBase64);
}

export async function decryptRoomReaction(ciphertextB64, nonceB64, roomKeyBase64) {
  const raw = await decryptRoomMessage(ciphertextB64, nonceB64, roomKeyBase64);
  return JSON.parse(raw);
}

export async function encryptRoomTopic(topic, roomKeyBase64) {
  return await encryptRoomMessage(topic, roomKeyBase64);
}

export async function decryptRoomTopic(ciphertextB64, nonceB64, roomKeyBase64) {
  return await decryptRoomMessage(ciphertextB64, nonceB64, roomKeyBase64);
}