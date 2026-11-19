import { describe, it, expect } from 'vitest';
import { get } from 'svelte/store';
import { locale, t, getLanguages } from '../lib/i18n.js';

describe('i18n Localization Store', () => {
  it('returns translations for English and Spanish', () => {
    locale.set('en');
    const translateEn = get(t);
    expect(translateEn('auth.login_title')).toBe('Organization Login');
    expect(translateEn('submit.title')).toBe('📨 Anonymous Submission');
    expect(translateEn('submit.passphrase_label')).toBe('Your Decryption Passphrase:');

    locale.set('es');
    const translateEs = get(t);
    expect(translateEs('auth.login_title')).toBe('Inicio de Sesión de la Organización');
    expect(translateEs('submit.title')).toBe('📨 Envío Anónimo');
    expect(translateEs('submit.passphrase_label')).toBe('Tu Frase de Paso de Desencriptación:');
  });

  it('exposes available language list', () => {
    const langs = getLanguages();
    expect(langs).toEqual([
      { code: 'en', name: 'English' },
      { code: 'es', name: 'Español' },
    ]);
  });
});
