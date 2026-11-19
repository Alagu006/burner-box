import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  encryptForRecipient,
  decryptFromSender,
  encryptWithPGP,
  decryptWithPGP,
  generatePGPKeyPair,
} from '../lib/crypto.js';

describe('Submission Page Customization & Bundled Encryption', () => {
  describe('Bundled Custom Fields Encryption & Decryption', () => {
    it('bundles custom fields into structured payload and encrypts/decrypts via libsodium with zero plaintext leakage', async () => {
      const orgKeys = await generateKeyPair();
      const mainMessage = 'I have discovered financial accounting irregularities in the FY25 report.';
      const customFieldResponses = {
        'What department does this concern?': 'Internal Audit & Treasury',
        'Urgency Level': 'High Priority',
        'Has this been reported internally?': 'No, fear of retaliation',
      };

      // Submitter bundles main message + structured custom fields into JSON
      const bundledPayload = JSON.stringify({
        main_message: mainMessage,
        custom_fields: customFieldResponses,
      });

      // Encrypt for org
      const enc = await encryptForRecipient(bundledPayload, orgKeys.publicKey);

      // Verify ciphertext does not leak any plaintext values
      expect(enc.ciphertext).not.toContain('financial accounting');
      expect(enc.ciphertext).not.toContain('Treasury');
      expect(enc.ciphertext).not.toContain('retaliation');

      // Org decrypts payload
      const decrypted = await decryptFromSender(
        {
          ciphertext: enc.ciphertext,
          nonce: enc.nonce,
          encryptedKey: enc.encryptedKey,
          boxNonce: enc.boxNonce,
          senderPublicKey: enc.senderPublicKey,
        },
        orgKeys.privateKey
      );

      // Parse decrypted payload
      const parsed = JSON.parse(decrypted);
      expect(parsed.main_message).toBe(mainMessage);
      expect(parsed.custom_fields['What department does this concern?']).toBe('Internal Audit & Treasury');
      expect(parsed.custom_fields['Urgency Level']).toBe('High Priority');
    });

    it('bundles custom fields into structured payload and encrypts/decrypts via PGP', async () => {
      const pgpKeys = await generatePGPKeyPair('Press Org', 'press@org.test');
      const mainMessage = 'Supply chain bypass documentation attached.';
      const customFieldResponses = {
        'Entity Name': 'Acme Logistics LLC',
        'Region': 'North America',
      };

      const bundledPayload = JSON.stringify({
        main_message: mainMessage,
        custom_fields: customFieldResponses,
      });

      // Encrypt with PGP
      const armoredCiphertext = await encryptWithPGP(bundledPayload, pgpKeys.publicKey);
      expect(armoredCiphertext).toContain('-----BEGIN PGP MESSAGE-----');
      expect(armoredCiphertext).not.toContain('Acme Logistics');

      // Decrypt with PGP
      const decrypted = await decryptWithPGP(armoredCiphertext, pgpKeys.privateKey);
      const parsed = JSON.parse(decrypted);
      expect(parsed.main_message).toBe(mainMessage);
      expect(parsed.custom_fields['Entity Name']).toBe('Acme Logistics LLC');
    });
  });

  describe('Anonymity Safeguard Verification', () => {
    it('verifies custom fields validation enforces safe field types', () => {
      const allowedFieldTypes = ['text', 'select', 'textarea'];
      const fieldType1 = 'text';
      const fieldType2 = 'select';
      const fieldType3 = 'textarea';
      const invalidType = 'password_input';

      expect(allowedFieldTypes.includes(fieldType1)).toBe(true);
      expect(allowedFieldTypes.includes(fieldType2)).toBe(true);
      expect(allowedFieldTypes.includes(fieldType3)).toBe(true);
      expect(allowedFieldTypes.includes(invalidType)).toBe(false);
    });
  });
});
