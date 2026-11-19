/**
 * Client-Side Synthetic Voice & Text-to-Speech (TTS) Module
 * 
 * SECURITY & PRIVACY GUARANTEE:
 * - Uses browser SpeechSynthesis API (window.speechSynthesis) and Web Audio API synthesis.
 * - ZERO microphone access (NO getUserMedia, NO MediaRecorder audio streams).
 * - The submitter's actual voice is NEVER recorded or uploaded.
 */

/**
 * Check if browser supports SpeechSynthesis
 * @returns {boolean}
 */
export function isSpeechSynthesisSupported() {
  return typeof window !== 'undefined' && 'speechSynthesis' in window;
}

/**
 * Get available system voices
 * @returns {SpeechSynthesisVoice[]}
 */
export function getSystemVoices() {
  if (!isSpeechSynthesisSupported()) return [];
  return window.speechSynthesis.getVoices() || [];
}

/**
 * Preview message aloud using browser SpeechSynthesis with a generic system voice
 * @param {string} text - Message to speak
 * @param {Object} [options]
 * @param {SpeechSynthesisVoice} [options.voice]
 * @param {number} [options.rate=1.0] - Speed (0.5 - 2.0)
 * @param {number} [options.pitch=1.0] - Pitch (0.5 - 1.5)
 * @param {() => void} [options.onStart]
 * @param {() => void} [options.onEnd]
 * @param {(err: any) => void} [options.onError]
 * @returns {SpeechSynthesisUtterance | null}
 */
export function previewSpeech(text, options = {}) {
  if (!isSpeechSynthesisSupported() || !text || !text.trim()) {
    return null;
  }

  // Cancel any ongoing speech first
  window.speechSynthesis.cancel();

  const utterance = new SpeechSynthesisUtterance(text.trim());
  utterance.rate = options.rate ?? 1.0;
  utterance.pitch = options.pitch ?? 1.0;

  if (options.voice) {
    utterance.voice = options.voice;
  }

  if (options.onStart) utterance.onstart = options.onStart;
  if (options.onEnd) utterance.onend = options.onEnd;
  if (options.onError) utterance.onerror = options.onError;

  window.speechSynthesis.speak(utterance);
  return utterance;
}

/**
 * Stop any active SpeechSynthesis playback
 */
export function stopSpeech() {
  if (isSpeechSynthesisSupported()) {
    window.speechSynthesis.cancel();
  }
}

/**
 * Generate a standalone synthetic audio WAV Blob from text entirely client-side.
 * Synthesizes acoustic computer voice formants and cadences for words and letters
 * into a standard 16-bit PCM RIFF/WAV file without using any microphone.
 * 
 * @param {string} text - Text to synthesize into audio
 * @param {Object} [options]
 * @param {number} [options.sampleRate=22050]
 * @returns {Promise<Blob>} - audio/wav Blob
 */
export async function generateSyntheticAudioBlob(text, options = {}) {
  const cleanText = (text || '').trim();
  if (!cleanText) {
    throw new Error('Text cannot be empty for synthetic audio generation');
  }

  const sampleRate = options.sampleRate || 22050;
  const words = cleanText.split(/\s+/).filter(Boolean);
  
  // Calculate duration based on words and punctuation
  // Average speaking pace: ~140 words per minute ≈ 430ms per word
  const wordDuration = 0.35; // seconds per word
  const pauseDuration = 0.12; // pause between words
  const totalDuration = Math.max(1.0, words.length * (wordDuration + pauseDuration) + 0.3);
  const totalSamples = Math.floor(sampleRate * totalDuration);

  // Allocate 16-bit PCM buffer (mono)
  const pcmData = new Int16Array(totalSamples);

  // Vowel formant frequencies (F1, F2 in Hz) for synthetic speech simulation
  const formants = [
    { f1: 730, f2: 1090 }, // 'a'
    { f1: 530, f2: 1840 }, // 'e'
    { f1: 270, f2: 2290 }, // 'i'
    { f1: 570, f2: 840 },  // 'o'
    { f1: 300, f2: 870 },  // 'u'
  ];

  let currentSampleOffset = 0;

  for (let w = 0; w < words.length; w++) {
    const word = words[w].toLowerCase();
    const wordSamples = Math.floor(sampleRate * wordDuration);
    const baseFreq = 130 + (w % 4) * 8 - (w % 3) * 5; // Slight intonation contour (120-150 Hz)

    // Formant selection based on word characters
    const charCodeSum = word.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
    const formant = formants[charCodeSum % formants.length];

    for (let i = 0; i < wordSamples && (currentSampleOffset + i) < totalSamples; i++) {
      const t = i / sampleRate;
      const progress = i / wordSamples;

      // Amplitude envelope (attack - sustain - decay)
      let env = 1.0;
      if (progress < 0.15) {
        env = progress / 0.15; // Attack
      } else if (progress > 0.8) {
        env = (1.0 - progress) / 0.2; // Decay
      }

      // Fundamental pitch + Formant harmonic synthesis
      const fundamental = Math.sin(2 * Math.PI * baseFreq * t);
      const f1Harmonic = 0.6 * Math.sin(2 * Math.PI * formant.f1 * t);
      const f2Harmonic = 0.4 * Math.sin(2 * Math.PI * formant.f2 * t);
      const noise = (Math.random() * 2 - 1) * 0.05; // Subtle acoustic breathiness

      const mixed = (fundamental * 0.5 + f1Harmonic + f2Harmonic + noise) * env * 0.7;

      // Convert to 16-bit signed PCM
      const sampleVal = Math.max(-1, Math.min(1, mixed));
      pcmData[currentSampleOffset + i] = sampleVal < 0 ? sampleVal * 0x8000 : sampleVal * 0x7FFF;
    }

    currentSampleOffset += wordSamples;

    // Add brief inter-word pause
    const pauseSamples = Math.floor(sampleRate * pauseDuration);
    currentSampleOffset += pauseSamples;
  }

  // Build RIFF/WAV Header
  const wavBuffer = createWavFileBuffer(pcmData, sampleRate, 1);
  return new Blob([wavBuffer], { type: 'audio/wav' });
}

/**
 * Encodes PCM data into a RIFF WAVE ArrayBuffer
 * @param {Int16Array} pcmData - 16-bit mono PCM samples
 * @param {number} sampleRate - e.g. 22050 or 44100
 * @param {number} numChannels - 1 (mono)
 * @returns {ArrayBuffer}
 */
function createWavFileBuffer(pcmData, sampleRate, numChannels = 1) {
  const bytesPerSample = 2; // 16-bit
  const blockAlign = numChannels * bytesPerSample;
  const byteRate = sampleRate * blockAlign;
  const dataSize = pcmData.length * bytesPerSample;
  const buffer = new ArrayBuffer(44 + dataSize);
  const view = new DataView(buffer);

  // Write ASCII string helper
  const writeString = (offset, string) => {
    for (let i = 0; i < string.length; i++) {
      view.setUint8(offset + i, string.charCodeAt(i));
    }
  };

  // RIFF identifier
  writeString(0, 'RIFF');
  // RIFF chunk length (36 + SubChunk2Size)
  view.setUint32(4, 36 + dataSize, true);
  // WAVE identifier
  writeString(8, 'WAVE');

  // fmt sub-chunk
  writeString(12, 'fmt ');
  // Subchunk1Size (16 for PCM)
  view.setUint32(16, 16, true);
  // AudioFormat (1 = PCM)
  view.setUint16(20, 1, true);
  // NumChannels
  view.setUint16(22, numChannels, true);
  // SampleRate
  view.setUint32(24, sampleRate, true);
  // ByteRate
  view.setUint32(28, byteRate, true);
  // BlockAlign
  view.setUint16(32, blockAlign, true);
  // BitsPerSample
  view.setUint16(34, 16, true);

  // data sub-chunk
  writeString(36, 'data');
  // Subchunk2Size (data size in bytes)
  view.setUint32(40, dataSize, true);

  // Write PCM audio samples
  let offset = 44;
  for (let i = 0; i < pcmData.length; i++, offset += 2) {
    view.setInt16(offset, pcmData[i], true);
  }

  return buffer;
}
