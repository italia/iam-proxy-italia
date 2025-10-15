import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import svgr from 'vite-plugin-svgr';
import eslint from 'vite-plugin-eslint';
import { VitePWA } from 'vite-plugin-pwa';
import { ManifestPlugin, RobotsTxtPlugin, SitemapPlugin } from './vite-plugins';

export default defineConfig(({ mode }) => {
	const env = loadEnv(mode, process.cwd(), '')
	return {
		base: '/wwwallet-frontend/',
		plugins: [
			react(),
			svgr(),
			eslint(),
			ManifestPlugin(env),
			RobotsTxtPlugin(env),
			SitemapPlugin(env),
			VitePWA({
				registerType: 'autoUpdate',
				srcDir: 'src',
				filename: 'service-worker.js', // Custom service worker (MUST exist in `src/`)
				strategies: 'injectManifest', // Uses `src/service-worker.js` for caching
				manifest: false, // Vite will use `public/manifest.json` automatically
				injectManifest: {
					maximumFileSizeToCacheInBytes: 3 * 1024 * 1024,
				},
			}),

		],
		resolve: {
			alias: {
				'@': '/src',
			},
		},
		server: {
			host: true,
			port: 3000,
			open: true,
		},
		preview: {
			host: true,
			port: 3000,
			open: true,
		},
		build: {
			sourcemap: env.VITE_GENERATE_SOURCEMAP === 'true',
		},
	}
});
