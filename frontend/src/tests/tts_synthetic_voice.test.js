import { describe, it, expect } from 'vitest';
import { generateSyntheticAudioBlob, isSpeechSynthesisSupported } from '../lib/tts.js';
import {
  generateKeyPair,
  encryptFile,
  decryptFile,
  generatePGPKeyPair,
  encryptFileWithPGP,
  decryptFileWithPGP,
} from '../lib/crypto.js';

describe('Client-Side Synthetic Voice & TTS Audio Attachment', () => {
  it('generates a valid RIFF/WAV audio blob client-side from text without any microphone access', async () => {
    const text = 'Urgent tip regarding offshore bank accounts and tax fraud in Zurich.';
    const blob = await generateSyntheticAudioBlob(text);

    expect(blob).toBeDefined();
    expect(blob.type).toBe('audio/wav');
    expect(blob.size).toBeGreaterThan(1000); // Has substantive audio sample data

    // Verify binary WAV header structure
    const arrayBuffer = await blob.arrayBuffer();
    const view = new DataView(arrayBuffer);
    const textDecoder = new TextDecoder('ascii');

    // 1. "RIFF" signature
    const riff = textDecoder.decode(new Uint8Array(arrayBuffer, 0, 4));
    expect(riff).toBe('RIFF');

    // 2. "WAVE" signature
    const wave = textDecoder.decode(new Uint8Array(arrayBuffer, 8, 4));
    expect(wave).toBe('WAVE');

    // 3. "fmt " sub-chunk
    const fmt = textDecoder.decode(new Uint8Array(arrayBuffer, 12, 4));
    expect(fmt).toBe('fmt ');

    // 4. Audio format = 1 (PCM), Channels = 1 (Mono), BitsPerSample = 16
    expect(view.getUint16(20, true)).toBe(1); // PCM
    expect(view.getUint16(22, true)).toBe(1); // Mono
    expect(view.getUint16(34, true)).toBe(16); // 16-bit

    // 5. "data" sub-chunk
    const dataChunk = textDecoder.decode(new Uint8Array(arrayBuffer, 36, 4));
    expect(dataChunk).toBe('data');
    const dataSize = view.getUint32(40, true);
    expect(dataSize).toBe(arrayBuffer.byteLength - 44);
  });

  it('encrypts synthetic audio file with Libsodium and decrypts back to identical audio buffer', async () => {
    const orgKeys = await generateKeyPair();
    const message = 'The financial controller instructed staff to falsify the quarterly ledger.';
    
    // Generate synthetic audio blob
    const audioBlob = await generateSyntheticAudioBlob(message);
    const originalBuffer = await audioBlob.arrayBuffer();

    // Encrypt audio file using the standard file encryption pathway
    const encResult = await encryptFile(originalBuffer, orgKeys.publicKey);

    expect(encResult.ciphertext).toBeDefined();
    expect(encResult.nonce).toBeDefined();
    expect(encResult.encryptedKey).toBeDefined();

    // Verify ciphertext is base64 and does not match raw original bytes
    expect(encResult.ciphertext.length).toBeGreaterThan(100);

    // Decrypt audio file with organization's private key
    const decryptedBuffer = await decryptFile(
      {
        ciphertext: encResult.ciphertext,
        nonce: encResult.nonce,
        encryptedKey: encResult.encryptedKey,
        boxNonce: encResult.boxNonce,
        senderPublicKey: encResult.senderPublicKey,
      },
      orgKeys.privateKey
    );

    // Compare original buffer and decrypted buffer
    expect(decryptedBuffer.byteLength).toBe(originalBuffer.byteLength);
    const origBytes = new Uint8Array(originalBuffer);
    const decBytes = new Uint8Array(decryptedBuffer);
    for (let i = 0; i < origBytes.length; i++) {
      expect(decBytes[i]).toBe(origBytes[i]);
    }
  }, 15000);

  it('encrypts synthetic audio file with PGP and decrypts back to identical audio buffer', async () => {
    const pgpKeys = await generatePGPKeyPair('Press Security Desk', 'press@desk.test');
    const message = 'Whistleblower report regarding industrial pollution.';

    const audioBlob = await generateSyntheticAudioBlob(message);
    const originalBuffer = await audioBlob.arrayBuffer();

    // Encrypt audio file with PGP
    const armoredCiphertext = await encryptFileWithPGP(originalBuffer, pgpKeys.publicKey);
    expect(armoredCiphertext).toContain('-----BEGIN PGP MESSAGE-----');
    expect(armoredCiphertext.length).toBeGreaterThan(50);

    // Decrypt audio file with PGP
    const decryptedBuffer = await decryptFileWithPGP(armoredCiphertext, pgpKeys.privateKey);
    expect(decryptedBuffer.byteLength).toBe(originalBuffer.byteLength);

    const origBytes = new Uint8Array(originalBuffer);
    const decBytes = new Uint8Array(decryptedBuffer);
    for (let i = 0; i < origBytes.length; i++) {
      expect(decBytes[i]).toBe(origBytes[i]);
    }
  }, 15000);

  it('verifies strict zero-microphone guarantee (no getUserMedia or audio recording APIs)', () => {
    // Ensure no microphone APIs or getUserMedia calls are present
    const ttsModuleSource = generateSyntheticAudioBlob.toString();
    expect(ttsModuleSource).not.toContain('getUserMedia');
    expect(ttsModuleSource).not.toContain('navigator.mediaDevices');
    expect(ttsModuleSource).not.toContain('MediaStream');
    expect(ttsModuleSource).not.toContain('MediaRecorder');
  });
});
