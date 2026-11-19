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

    // Auth / Login
    'auth.login_title': 'Organization Login',
    'auth.email': 'Email',
    'auth.password': 'Password',
    'auth.login_btn': '🔐 Login',
    'auth.logging_in': 'Logging in...',
    'auth.login_success': '✅ Login Successful!',
    'auth.redirecting': 'Redirecting to dashboard...',
    'auth.2fa_prompt': 'Enter the 6-digit code from your authenticator app.',
    'auth.2fa_label': 'Authentication Code',
    'auth.verify_btn': '🔐 Verify',
    'auth.verifying': 'Verifying...',
    'auth.back_to_login': '← Back to login',
    'auth.no_account': "Don't have an account?",
    'auth.signup_link': 'Sign up',

    // Signup
    'signup.title': 'Register Your Organization',
    'signup.org_name': 'Organization Name',
    'signup.org_name_placeholder': 'The Daily News',
    'signup.email_placeholder': 'org@example.com',
    'signup.password_placeholder': 'Min. 8 characters',
    'signup.confirm_password': 'Confirm Password',
    'signup.confirm_placeholder': 'Repeat password',
    'signup.register_btn': '🚀 Register Organization',
    'signup.generating_keys': '🔐 Generating Encryption Keys...',
    'signup.creating_account': 'Creating Account...',
    'signup.already_registered': 'Already registered?',
    'signup.login_link': 'Log in',
    'signup.success_title': '✅ Registration Successful!',
    'signup.secret_url_hint': 'Share this secret URL with sources to receive anonymous tips:',
    'signup.copy_url': '📋 Copy URL',
    'signup.redirect_countdown': '⏳ Redirecting to login in',
    'signup.seconds': 'seconds...',
    'signup.key_warning': '⚠️ Your encryption key is stored in this browser. Don\'t clear browser data or you\'ll lose access to encrypted submissions.',
    'signup.go_to_login': '🔐 Go to Login Now →',

    // Submit
    'submit.title': '📨 Anonymous Submission',
    'submit.subtitle': 'Your identity is protected. No IP logs, no tracking.',
    'submit.submitting_to': 'Submitting to:',
    'submit.encryption_ready': '✅ Encryption ready',
    'submit.checking_encryption': '🔐 Checking encryption...',
    'submit.closed_title': '⛔ Submission Portal Closed',
    'submit.closed_desc': 'This organization is no longer accepting submissions.',
    'submit.message_label': 'Your Message',
    'submit.message_placeholder': 'Type your anonymous tip here...',
    'submit.attach_files': 'Attach Files (Optional)',
    'submit.max_file_hint': 'Max 10MB per file. Files are encrypted before upload.',
    'submit.allow_replies': 'Allow the organization to reply to this submission',
    'submit.reply_hint': 'A unique encryption keypair will be generated and encrypted with a local passphrase.',
    'submit.send_btn': '🔒 Send Encrypted Anonymously',
    'submit.encryption_not_ready': '🔒 Encryption not ready',
    'submit.encrypting': '🔐 Encrypting your submission...',
    'submit.sending': '📤 Sending encrypted submission...',
    'submit.quick_exit': '⚡ QUICK EXIT',
    'submit.success_title': 'Submission Sent Successfully',
    'submit.identity_label': 'Your Anonymous Identity:',
    'submit.identity_warning': '⚠️ Save this name! You\'ll need it to check for replies. We will NEVER show this again.',
    'submit.passphrase_label': 'Your Decryption Passphrase:',
    'submit.passphrase_warning': '⚠️ Save this passphrase! You will need BOTH your anonymous name and this passphrase to unlock replies.',
    'submit.copy_passphrase': '📋 Copy Passphrase',
    'submit.files_uploaded': '📎 Files Uploaded',
    'submit.proof_title': '📜 Proof of Submission',
    'submit.proof_desc': 'A cryptographic receipt signed by the server. You can independently verify that your submission was received at the stated time.',
    'submit.download_proof': '⬇️ Download Proof (.txt)',
    'submit.replies_enabled': '📬 E2E Encrypted Replies Enabled',
    'submit.replies_desc': 'The organization can reply. Your decryption key is encrypted with your passphrase in this browser.',
    'submit.exit_safely': '🚪 Exit Safely',
    'submit.security_note': '🔒 Your message is encrypted in your browser before being sent. The server never sees the plaintext. We never log IP addresses.',

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

    // Auth / Login
    'auth.login_title': 'Inicio de Sesión de la Organización',
    'auth.email': 'Correo electrónico',
    'auth.password': 'Contraseña',
    'auth.login_btn': '🔐 Iniciar Sesión',
    'auth.logging_in': 'Iniciando sesión...',
    'auth.login_success': '✅ ¡Inicio de Sesión Exitoso!',
    'auth.redirecting': 'Redirigiendo al panel...',
    'auth.2fa_prompt': 'Ingresa el código de 6 dígitos de tu aplicación de autenticación.',
    'auth.2fa_label': 'Código de Autenticación',
    'auth.verify_btn': '🔐 Verificar',
    'auth.verifying': 'Verificando...',
    'auth.back_to_login': '← Volver al inicio de sesión',
    'auth.no_account': '¿No tienes una cuenta?',
    'auth.signup_link': 'Regístrate',

    // Signup
    'signup.title': 'Registra tu Organización',
    'signup.org_name': 'Nombre de la Organización',
    'signup.org_name_placeholder': 'El Diario de Noticias',
    'signup.email_placeholder': 'org@ejemplo.com',
    'signup.password_placeholder': 'Mín. 8 caracteres',
    'signup.confirm_password': 'Confirmar Contraseña',
    'signup.confirm_placeholder': 'Repite la contraseña',
    'signup.register_btn': '🚀 Registrar Organización',
    'signup.generating_keys': '🔐 Generando Claves de Encriptación...',
    'signup.creating_account': 'Creando Cuenta...',
    'signup.already_registered': '¿Ya estás registrado?',
    'signup.login_link': 'Inicia sesión',
    'signup.success_title': '✅ ¡Registro Exitoso!',
    'signup.secret_url_hint': 'Comparte esta URL secreta con fuentes para recibir consejos anónimos:',
    'signup.copy_url': '📋 Copiar URL',
    'signup.redirect_countdown': '⏳ Redirigiendo al inicio de sesión en',
    'signup.seconds': 'segundos...',
    'signup.key_warning': '⚠️ Tu clave de encriptación está guardada en este navegador. No borres los datos del navegador o perderás el acceso a los envíos encriptados.',
    'signup.go_to_login': '🔐 Ir al Inicio de Sesión Ahora →',

    // Submit
    'submit.title': '📨 Envío Anónimo',
    'submit.subtitle': 'Tu identidad está protegida. Sin registros de IP, sin rastreo.',
    'submit.submitting_to': 'Enviando a:',
    'submit.encryption_ready': '✅ Encriptación lista',
    'submit.checking_encryption': '🔐 Verificando encriptación...',
    'submit.closed_title': '⛔ Portal de Envíos Cerrado',
    'submit.closed_desc': 'Esta organización ya no acepta envíos.',
    'submit.message_label': 'Tu Mensaje',
    'submit.message_placeholder': 'Escribe tu consejo anónimo aquí...',
    'submit.attach_files': 'Adjuntar Archivos (Opcional)',
    'submit.max_file_hint': 'Máx. 10MB por archivo. Los archivos se encriptan antes de enviarse.',
    'submit.allow_replies': 'Permitir que la organización responda a este envío',
    'submit.reply_hint': 'Se generará un par de claves único y se encriptará con una frase de paso local.',
    'submit.send_btn': '🔒 Enviar Encriptado de Forma Anónima',
    'submit.encryption_not_ready': '🔒 Encriptación no disponible',
    'submit.encrypting': '🔐 Encriptando tu envío...',
    'submit.sending': '📤 Enviando envío encriptado...',
    'submit.quick_exit': '⚡ SALIDA RÁPIDA',
    'submit.success_title': 'Envío Enviado Exitosamente',
    'submit.identity_label': 'Tu Identidad Anónima:',
    'submit.identity_warning': '⚠️ ¡Guarda este nombre! Lo necesitarás para verificar respuestas. NUNCA lo volveremos a mostrar.',
    'submit.passphrase_label': 'Tu Frase de Paso de Desencriptación:',
    'submit.passphrase_warning': '⚠️ ¡Guarda esta frase de paso! Necesitarás TANTO tu nombre anónimo como esta frase de paso para desbloquear respuestas.',
    'submit.copy_passphrase': '📋 Copiar Frase de Paso',
    'submit.files_uploaded': '📎 Archivos Subidos',
    'submit.proof_title': '📜 Prueba de Envío',
    'submit.proof_desc': 'Un recibo criptográfico firmado por el servidor. Puedes verificar independientemente que tu envío fue recibido en la hora indicada.',
    'submit.download_proof': '⬇️ Descargar Prueba (.txt)',
    'submit.replies_enabled': '📬 Respuestas Encriptadas E2E Habilitadas',
    'submit.replies_desc': 'La organización puede responder. Tu clave de desencriptación está encriptada con tu frase de paso en este navegador.',
    'submit.exit_safely': '🚪 Salir de Forma Segura',
    'submit.security_note': '🔒 Tu mensaje se encripta en tu navegador antes de enviarse. El servidor nunca ve el texto plano. Nunca registramos direcciones IP.',

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
