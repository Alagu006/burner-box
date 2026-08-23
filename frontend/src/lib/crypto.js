import sodium from 'libsodium-wrappers';

// Initialize sodium
let sodiumReady = null;
async function getSodium() {
  if (!sodiumReady) {
    sodiumReady = sodium.ready;
  }
  await sodiumReady;
  return sodium;
}

// Generate a key pair for the organization
export async function generateKeyPair() {
  const s = await getSodium();
  const keyPair = s.crypto_box_keypair();
  return {
    publicKey: s.to_base64(keyPair.publicKey, s.base64_variants.ORIGINAL),
    privateKey: s.to_base64(keyPair.privateKey, s.base64_variants.ORIGINAL),
  };
}

// Encrypt a message for a recipient's public key
// Returns { ciphertext, nonce, encryptedKey } 
// where encryptedKey is the symmetric key encrypted with recipient's public key
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

// Decrypt a message using recipient's private key
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

// Encrypt a file (ArrayBuffer) for a recipient
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

// Decrypt a file
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

// ---- Key-at-rest encryption (Argon2id + AES) ----
// Encrypts/decrypts private keys stored in localStorage using a key
// derived from the user's password via Argon2id (memory-hard KDF).

let _cachedDerivedKey = null;

// Derive a 32-byte key from a password using Argon2id.
// The salt should be stored alongside the encrypted key.
export async function deriveKeyFromPassword(password, saltBase64) {
  const s = await getSodium();
  const salt = s.from_base64(saltBase64, s.base64_variants.ORIGINAL);
  return s.crypto_pwhash(
    s.crypto_secretbox_KEYBYTES,
    password,
    salt,
    s.crypto_pwhash_OPSLIMIT_SENSITIVE,
    s.crypto_pwhash_MEMLIMIT_SENSITIVE,
    s.crypto_pwhash_ALG_ARGON2ID13
  );
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

// Read the org private key from localStorage, handling both legacy (raw base64)
// and encrypted (JSON with salt/nonce) formats. Returns null if not found or
// cannot decrypt.
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

// Encrypt a private key for localStorage storage.
// Returns { encryptedPrivateKey, salt } (both base64).
export async function encryptPrivateKey(privateKeyBase64, password) {
  const s = await getSodium();
  const salt = s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
  const key = await deriveKeyFromPassword(password, s.to_base64(salt, s.base64_variants.ORIGINAL));
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const plaintext = s.from_base64(privateKeyBase64, s.base64_variants.ORIGINAL);
  const ciphertext = s.crypto_secretbox_easy(plaintext, nonce, key);
  return {
    encryptedPrivateKey: s.to_base64(ciphertext, s.base64_variants.ORIGINAL),
    salt: s.to_base64(salt, s.base64_variants.ORIGINAL),
    nonce: s.to_base64(nonce, s.base64_variants.ORIGINAL),
  };
}

// Decrypt a private key stored in localStorage.
// Returns the private key as a base64 string.
export async function decryptPrivateKey(encryptedB64, saltBase64, nonceBase64, password) {
  const s = await getSodium();
  const key = await deriveKeyFromPassword(password, saltBase64);
  const ciphertext = s.from_base64(encryptedB64, s.base64_variants.ORIGINAL);
  const nonce = s.from_base64(nonceBase64, s.base64_variants.ORIGINAL);
  const plaintext = s.crypto_secretbox_open_easy(ciphertext, nonce, key);
  return s.to_base64(plaintext, s.base64_variants.ORIGINAL);
}

// ---- Room encryption (symmetric, shared key via URL fragment) ----

// Generate a random symmetric key for a room
export async function generateRoomKey() {
  const s = await getSodium();
  const key = s.randombytes_buf(s.crypto_secretbox_KEYBYTES);
  return s.to_base64(key, s.base64_variants.ORIGINAL);
}

// Encrypt a room message with the shared room key
export async function encryptRoomMessage(plaintext, roomKeyBase64) {
  const s = await getSodium();
  const key = s.from_base64(roomKeyBase64, s.base64_variants.ORIGINAL);
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const ciphertext = s.crypto_secretbox_easy(plaintext, nonce, key);

  return {
    ciphertext: s.to_base64(ciphertext, s.base64_variants.ORIGINAL),
    nonce: s.to_base64(nonce, s.base64_variants.ORIGINAL),
  };
}

// Decrypt a room message with the shared room key
export async function decryptRoomMessage(ciphertextB64, nonceB64, roomKeyBase64) {
  const s = await getSodium();
  const key = s.from_base64(roomKeyBase64, s.base64_variants.ORIGINAL);
  const nonce = s.from_base64(nonceB64, s.base64_variants.ORIGINAL);
  const ciphertext = s.from_base64(ciphertextB64, s.base64_variants.ORIGINAL);

  const plaintext = s.crypto_secretbox_open_easy(ciphertext, nonce, key);
  return new TextDecoder().decode(plaintext);
}

// ---- Room file encryption (same symmetric key as messages) ----

// Encrypt a file for a room using the shared room key.
// Returns { ciphertext (base64), nonce (base64) }.
export async function encryptRoomFile(fileArrayBuffer, roomKeyBase64) {
  const s = await getSodium();
  const key = s.from_base64(roomKeyBase64, s.base64_variants.ORIGINAL);
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const ciphertext = s.crypto_secretbox_easy(new Uint8Array(fileArrayBuffer), nonce, key);
  return {
    ciphertext: s.to_base64(ciphertext, s.base64_variants.ORIGINAL),
    nonce: s.to_base64(nonce, s.base64_variants.ORIGINAL),
  };
}

// Decrypt a room file using the shared room key.
// Returns an ArrayBuffer of the decrypted file data.
export async function decryptRoomFile(ciphertextB64, nonceB64, roomKeyBase64) {
  const s = await getSodium();
  const key = s.from_base64(roomKeyBase64, s.base64_variants.ORIGINAL);
  const nonce = s.from_base64(nonceB64, s.base64_variants.ORIGINAL);
  const ciphertext = s.from_base64(ciphertextB64, s.base64_variants.ORIGINAL);
  const plaintext = s.crypto_secretbox_open_easy(ciphertext, nonce, key);
  return plaintext.buffer;
}

// ---- Emoji reaction encryption (same room key) ----

// Encrypt an emoji reaction string with the room key.
export async function encryptRoomReaction(emoji, roomKeyBase64) {
  return encryptRoomMessage(emoji, roomKeyBase64);
}

// Decrypt an emoji reaction string with the room key.
export async function decryptRoomReaction(ciphertextB64, nonceB64, roomKeyBase64) {
  return decryptRoomMessage(ciphertextB64, nonceB64, roomKeyBase64);
}