import { describe, it, expect, beforeEach } from 'vitest';
import {
  generatePGPKeyPair,
  validatePGPPublicKey,
  encryptWithPGP,
  decryptWithPGP,
  encryptFileWithPGP,
  decryptFileWithPGP,
  encryptSubmission,
  decryptSubmission,
  setTransientPGPPrivateKey,
  getTransientPGPPrivateKey,
  clearTransientPGPPrivateKey,
  generateKeyPair,
} from '../lib/crypto.js';

describe('OpenPGP.js Integration & PGP End-to-End Flows', () => {
  beforeEach(() => {
    clearTransientPGPPrivateKey();
  });

  describe('PGP Key Generation & Armor Validation', () => {
    it('validates a well-formed ASCII-armored PGP public key', async () => {
      const { publicKey } = await generatePGPKeyPair('Press Org', 'press@outlet.test');
      expect(publicKey).toContain('-----BEGIN PGP PUBLIC KEY BLOCK-----');
      expect(publicKey).toContain('-----END PGP PUBLIC KEY BLOCK-----');

      const validation = await validatePGPPublicKey(publicKey);
      expect(validation.valid).toBe(true);
      expect(validation.keyID).toBeDefined();
    });

    it('rejects an invalid/malformed PGP public key with an error description', async () => {
      const invalidKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----\ncorrupted-random-bytes\n-----END PGP PUBLIC KEY BLOCK-----';
      const validation = await validatePGPPublicKey(invalidKey);
      expect(validation.valid).toBe(false);
      expect(validation.error).toBeDefined();
    });
  });

  describe('PGP Anonymous Tip Encryption and Decryption', () => {
    it('encrypts plaintext tip using PGP public key and decrypts with unencrypted private key', async () => {
      const { publicKey, privateKey } = await generatePGPKeyPair('Investigative Desk', 'desk@press.test');
      const secretTip = 'Top secret leak: Off-shore account transaction ledger ref #889922';

      // Submitter encrypts tip using org's PGP public key
      const armoredCiphertext = await encryptWithPGP(secretTip, publicKey);

      expect(armoredCiphertext).toContain('-----BEGIN PGP MESSAGE-----');
      expect(armoredCiphertext).toContain('-----END PGP MESSAGE-----');
      expect(armoredCiphertext).not.toContain('Off-shore account');

      // Org decrypts using PGP private key
      const decrypted = await decryptWithPGP(armoredCiphertext, privateKey);
      expect(decrypted).toBe(secretTip);
    });

    it('encrypts and decrypts with passphrase-protected PGP private key', async () => {
      const passphrase = 'UltraSecurePGPPassphrase2026!';
      const { publicKey, privateKey } = await generatePGPKeyPair('Sovereign Press', 'sovereign@press.test', passphrase);
      const secretTip = 'Whistleblower report on environmental compliance bypass';

      const armoredCiphertext = await encryptWithPGP(secretTip, publicKey);

      // Decryption with correct passphrase succeeds
      const decrypted = await decryptWithPGP(armoredCiphertext, privateKey, passphrase);
      expect(decrypted).toBe(secretTip);

      // Decryption with wrong passphrase fails
      await expect(
        decryptWithPGP(armoredCiphertext, privateKey, 'wrong-passphrase')
      ).rejects.toThrow();
    });
  });

  describe('PGP Binary File Encryption and Decryption', () => {
    it('encrypts binary file data with PGP public key and decrypts back to identical byte buffer', async () => {
      const { publicKey, privateKey } = await generatePGPKeyPair('Forensics Org', 'forensics@org.test');
      const fileData = new TextEncoder().encode('CONFIDENTIAL LEAK: Internal PDF binary stream simulation \x00\x01\x02\xFF').buffer;

      // Encrypt file client-side
      const armoredFileCiphertext = await encryptFileWithPGP(fileData, publicKey);
      expect(armoredFileCiphertext).toContain('-----BEGIN PGP MESSAGE-----');

      // Decrypt file on detail page
      const decryptedBuffer = await decryptFileWithPGP(armoredFileCiphertext, privateKey);
      const decryptedText = new TextDecoder().decode(decryptedBuffer);

      expect(decryptedText).toBe('CONFIDENTIAL LEAK: Internal PDF binary stream simulation \x00\x01\x02\xFF');
    });
  });

  describe('Transient In-Memory PGP Private Key Management', () => {
    it('stores PGP private key in browser memory only and clears properly without persisting', async () => {
      const { privateKey } = await generatePGPKeyPair('Temporary Session', 'session@org.test');
      const passphrase = 'MySessionPassphrase!';

      // Initially null
      expect(getTransientPGPPrivateKey()).toBeNull();

      // Set transient session key
      setTransientPGPPrivateKey(privateKey, passphrase);
      const retrieved = getTransientPGPPrivateKey();

      expect(retrieved).not.toBeNull();
      expect(retrieved.privateKey).toBe(privateKey.trim());
      expect(retrieved.passphrase).toBe(passphrase);

      // Clear on session end
      clearTransientPGPPrivateKey();
      expect(getTransientPGPPrivateKey()).toBeNull();
    });
  });

  describe('Unified encryptSubmission & decryptSubmission Scheme Branching', () => {
    it('demonstrates end-to-end PGP flow through unified submission helpers', async () => {
      const pgpKeys = await generatePGPKeyPair('PGP Org', 'pgp@org.test');
      const tipText = 'PGP Tip: Critical infrastructure audit report';

      // Encrypt with scheme = 'pgp'
      const enc = await encryptSubmission(tipText, pgpKeys.publicKey, 'pgp');
      expect(enc.encryptionMeta).toContain('"scheme":"pgp"');
      expect(enc.ciphertext).toContain('-----BEGIN PGP MESSAGE-----');

      // Decrypt using unified helper
      const decrypted = await decryptSubmission(enc.ciphertext, enc.encryptionMeta, pgpKeys.privateKey, 'pgp');
      expect(decrypted).toBe(tipText);
    });

    it('demonstrates end-to-end libsodium flow through unified submission helpers', async () => {
      const libsodiumKeys = await generateKeyPair();
      const tipText = 'libsodium Tip: Accounting anomalies spreadsheet';

      // Encrypt with scheme = 'libsodium'
      const enc = await encryptSubmission(tipText, libsodiumKeys.publicKey, 'libsodium');
      expect(enc.encryptionMeta).toContain('"scheme":"libsodium"');

      // Decrypt using unified helper
      const decrypted = await decryptSubmission(enc.ciphertext, enc.encryptionMeta, libsodiumKeys.privateKey, 'libsodium');
      expect(decrypted).toBe(tipText);
    });
  });
});
