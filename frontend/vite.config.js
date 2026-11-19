import adapter from '@sveltejs/adapter-cloudflare';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from "@tailwindcss/vite";
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode, command }) => {
	const env = loadEnv(mode, process.cwd(), '');
	const apiUrl = (process.env.VITE_API_URL || env.VITE_API_URL || '').trim();

	// Enforce HTTPS in production builds
	if (command === 'build' || mode === 'production') {
		if (apiUrl && !apiUrl.startsWith('https://')) {
			throw new Error(
				`SECURITY ERROR: In production builds, VITE_API_URL must start with https:// (got: ${apiUrl})`
			);
		}
	}

	return {
		plugins: [
			sveltekit({
				compilerOptions: {
					// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
					runes: ({ filename }) =>
						filename.split(/[/\\]/).includes('node_modules') ? undefined : true
				},
				// Cloudflare Pages adapter
				adapter: adapter()
			}),
			tailwindcss() // Seamlessly injects Tailwind v4 into the Vite pipeline
		]
	};
});
