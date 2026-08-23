// i18n scaffolding — lightweight translation system
// Framework for EN + ES proof of concept. Not all strings translated yet.

import { writable, derived } from 'svelte/store';

const STORAGE_KEY = 'burnerbox_lang';

// Translation dictionaries
const translations = {
  en: {
    // Navigation
    'nav.dashboard': 'Dashboard',
    'nav.submissions': 'Submissions',
    'nav.security': 'Security Settings',
    'nav.team': 'Team Management',
    'nav.create_room': 'Create Room',
    'nav.check_replies': 'Check Replies',
    'nav.login': 'Login',
    'nav.signup': 'Sign Up',
    'nav.logout': 'Logout',
    'nav.home': 'Home',
    'nav.back': '← Back',

    // Dashboard
    'dashboard.welcome': 'Welcome to your dashboard',
    'dashboard.total_submissions': 'Total Submissions',
    'dashboard.active_rooms': 'Active Rooms',

    // Submissions
    'submissions.title': 'Submissions',
    'submissions.loading': 'Loading submissions...',
    'submissions.empty': 'No submissions yet',
    'submissions.empty_hint': 'Share your submission portal URL to start receiving anonymous tips.',
    'submissions.mark_read': 'Mark Read',
    'submissions.actioned': 'Actioned',
    'submissions.archive': 'Archive',
    'submissions.export': 'Export',
    'submissions.clear': 'Clear',
    'submissions.priority': 'Priority',
    'submissions.status': 'Status',
    'submissions.assigned_to': 'Assigned to',

    // Security
    'security.title': 'Security Settings',
    'security.2fa': 'Two-Factor Authentication (2FA)',
    'security.2fa_enabled': '2FA is Enabled',
    'security.2fa_disabled': '2FA is Disabled',
    'security.2fa_enable': 'Enable 2FA',
    'security.2fa_disable': 'Disable 2FA',
    'security.key_rotation': 'Encryption Key Rotation',
    'security.retention': 'Data Retention Policy',
    'security.notifications': 'New Submission Notifications',

    // Room
    'room.title': 'Secure Room',
    'room.connect': 'Connect to Room',
    'room.connected': 'connected',
    'room.disconnected': 'disconnected',
    'room.send': 'Send',
    'room.type_message': 'Type an encrypted message...',
    'room.no_messages': 'No messages yet. Start the conversation.',
    'room.password_required': 'This room is password protected.',
    'room.join': 'Join Room',
    'room.slots': 'slots',

    // Common
    'common.save': 'Save',
    'common.cancel': 'Cancel',
    'common.delete': 'Delete',
    'common.confirm': 'Confirm',
    'common.loading': 'Loading...',
    'common.error': 'Error',
    'common.success': 'Success',
    'common.encrypted': 'End-to-end encrypted. The server never sees your plaintext.',

    // Accessibility
    'a11y.close': 'Close',
    'a11y.toggle_theme': 'Toggle light/dark theme',
    'a11y.command_palette': 'Open command palette',
  },

  es: {
    // Navigation
    'nav.dashboard': 'Panel',
    'nav.submissions': 'Envíos',
    'nav.security': 'Configuración de Seguridad',
    'nav.team': 'Gestión de Equipo',
    'nav.create_room': 'Crear Sala',
    'nav.check_replies': 'Verificar Respuestas',
    'nav.login': 'Iniciar Sesión',
    'nav.signup': 'Registrarse',
    'nav.logout': 'Cerrar Sesión',
    'nav.home': 'Inicio',
    'nav.back': '← Volver',

    // Dashboard
    'dashboard.welcome': 'Bienvenido a tu panel',
    'dashboard.total_submissions': 'Total de Envíos',
    'dashboard.active_rooms': 'Salas Activas',

    // Submissions
    'submissions.title': 'Envíos',
    'submissions.loading': 'Cargando envíos...',
    'submissions.empty': 'Sin envíos aún',
    'submissions.empty_hint': 'Comparte la URL de tu portal para recibir consejos anónimos.',
    'submissions.mark_read': 'Marcar Leído',
    'submissions.actioned': 'Acción Tomada',
    'submissions.archive': 'Archivar',
    'submissions.export': 'Exportar',
    'submissions.clear': 'Limpiar',
    'submissions.priority': 'Prioridad',
    'submissions.status': 'Estado',
    'submissions.assigned_to': 'Asignado a',

    // Security
    'security.title': 'Configuración de Seguridad',
    'security.2fa': 'Autenticación de Dos Factores (2FA)',
    'security.2fa_enabled': '2FA Está Habilitado',
    'security.2fa_disabled': '2FA Está Deshabilitado',
    'security.2fa_enable': 'Habilitar 2FA',
    'security.2fa_disable': 'Deshabilitar 2FA',
    'security.key_rotation': 'Rotación de Claves de Encriptación',
    'security.retention': 'Política de Retención de Datos',
    'security.notifications': 'Notificaciones de Nuevos Envíos',

    // Room
    'room.title': 'Sala Segura',
    'room.connect': 'Conectar a la Sala',
    'room.connected': 'conectado',
    'room.disconnected': 'desconectado',
    'room.send': 'Enviar',
    'room.type_message': 'Escribe un mensaje encriptado...',
    'room.no_messages': 'Sin mensajes aún. Inicia la conversación.',
    'room.password_required': 'Esta sala está protegida con contraseña.',
    'room.join': 'Unirse a la Sala',
    'room.slots': 'lugares',

    // Common
    'common.save': 'Guardar',
    'common.cancel': 'Cancelar',
    'common.delete': 'Eliminar',
    'common.confirm': 'Confirmar',
    'common.loading': 'Cargando...',
    'common.error': 'Error',
    'common.success': 'Éxito',
    'common.encrypted': 'Encriptado de extremo a extremo. El servidor nunca ve tu texto plano.',

    // Accessibility
    'a11y.close': 'Cerrar',
    'a11y.toggle_theme': 'Alternar tema claro/oscuro',
    'a11y.command_palette': 'Abrir paleta de comandos',
  },
};

// Current language store
const storedLang = typeof localStorage !== 'undefined' ? localStorage.getItem(STORAGE_KEY) : null;
export const locale = writable(storedLang || 'en');

// Subscribe to persist changes
locale.subscribe(lang => {
  if (typeof localStorage !== 'undefined') {
    localStorage.setItem(STORAGE_KEY, lang);
  }
});

// Translation function — derived from locale
export const t = derived(locale, ($locale) => {
  return (key) => {
    const dict = translations[$locale] || translations.en;
    return dict[key] || translations.en[key] || key;
  };
});

// Get available languages
export function getLanguages() {
  return Object.keys(translations).map(code => ({
    code,
    name: code === 'en' ? 'English' : code === 'es' ? 'Español' : code,
  }));
}
