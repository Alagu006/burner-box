import { describe, it, expect, beforeAll } from 'vitest';
import {
  generateKeyPair,
  generatePassphrase,
  encryptPrivateKey,
  decryptPrivateKey,
  encryptForRecipient,
  decryptFromSender,
  encryptFile,
  decryptFile,
} from '../lib/crypto.js';

describe('Frontend Cryptographic Security Flows', () => {
  beforeAll(async () => {
    const s = await import('libsodium-wrappers');
    await s.default.ready;
  });

  describe('Submitter Passphrase Generation & Key Encrypt/Unlock', () => {
    it('generatePassphrase produces high-entropy 4-word random passphrases', () => {
      const p1 = generatePassphrase();
      const p2 = generatePassphrase();
      expect(p1).not.toBe(p2);
      expect(p1).toMatch(/^[a-z]+-[a-z]+-[a-z]+-\d{4}$/);
    });

    it('encrypts reply private key with passphrase using Argon2id and decrypts successfully', async () => {
      const keyPair = await generateKeyPair();
      const passphrase = generatePassphrase();

      // Encrypt private key for localStorage
      const encResult = await encryptPrivateKey(keyPair.privateKey, passphrase);

      // Verify that ciphertext is NOT plaintext
      expect(encResult.encryptedPrivateKey).not.toBe(keyPair.privateKey);
      expect(encResult.salt).toBeDefined();
      expect(encResult.nonce).toBeDefined();

      // Unlock with correct passphrase
      const decryptedPrivateKey = await decryptPrivateKey(
        encResult.encryptedPrivateKey,
        encResult.salt,
        encResult.nonce,
        passphrase
      );

      expect(decryptedPrivateKey).toBe(keyPair.privateKey);
    });

    it('fails to unlock reply private key with wrong passphrase', async () => {
      const keyPair = await generateKeyPair();
      const passphrase = generatePassphrase();

      const encResult = await encryptPrivateKey(keyPair.privateKey, passphrase);

      // Attempt unlocking with wrong passphrase
      await expect(
        decryptPrivateKey(
          encResult.encryptedPrivateKey,
          encResult.salt,
          encResult.nonce,
          'wrong-passphrase-attempt-1234'
        )
      ).rejects.toThrow();
    });
  });

  describe('End-to-End Anonymous Tip Encryption & Reply Thread', () => {
    it('encrypts anonymous tip to org public key and recipient decrypts successfully', async () => {
      const orgKeyPair = await generateKeyPair();
      const plaintextTip = 'Sensitive leak: financial irregularities in Q3 report';

      // Submitter encrypts for org
      const enc = await encryptForRecipient(plaintextTip, orgKeyPair.publicKey);

      expect(enc.ciphertext).toBeDefined();
      expect(enc.ciphertext).not.toContain(plaintextTip);

      // Org decrypts using its private key
      const decrypted = await decryptFromSender(
        {
          ciphertext: enc.ciphertext,
          nonce: enc.nonce,
          encryptedKey: enc.encryptedKey,
          boxNonce: enc.boxNonce,
          senderPublicKey: enc.senderPublicKey,
        },
        orgKeyPair.privateKey
      );

      expect(decrypted).toBe(plaintextTip);
    });

    it('encrypts reply from org to submitter reply key and submitter decrypts', async () => {
      const replyKeyPair = await generateKeyPair();
      const orgReplyText = 'Thank you. We have verified the documents and are publishing tomorrow.';

      // Org encrypts reply to submitter's reply public key
      const encReply = await encryptForRecipient(orgReplyText, replyKeyPair.publicKey);

      // Submitter decrypts using unlocked reply private key
      const decryptedReply = await decryptFromSender(
        {
          ciphertext: encReply.ciphertext,
          nonce: encReply.nonce,
          encryptedKey: encReply.encryptedKey,
          boxNonce: encReply.boxNonce,
          senderPublicKey: encReply.senderPublicKey,
        },
        replyKeyPair.privateKey
      );

      expect(decryptedReply).toBe(orgReplyText);
    });
  });

  describe('Client-Side File Encryption & Decryption on Detail Page', () => {
    it('encrypts file client-side and decrypts properly using detail page pattern', async () => {
      const orgKeyPair = await generateKeyPair();
      const fileContent = new TextEncoder().encode('Confidential internal whistleblower document content 2026');

      // Client encrypts file before upload
      const encFileResult = await encryptFile(fileContent.buffer, orgKeyPair.publicKey);

      // Detail page constructs decryption object
      const decryptedFileBuffer = await decryptFile(
        {
          ciphertext: encFileResult.ciphertext,
          nonce: encFileResult.nonce,
          encryptedKey: encFileResult.encryptedKey,
          boxNonce: encFileResult.boxNonce,
          senderPublicKey: encFileResult.senderPublicKey,
        },
        orgKeyPair.privateKey
      );

      const decryptedText = new TextDecoder().decode(decryptedFileBuffer);
      expect(decryptedText).toBe('Confidential internal whistleblower document content 2026');
    });
  });
});
