import tailwindcss from '@tailwindcss/vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

// Builds to one self-contained index.html: no CDN, no network at runtime.
export default defineConfig({
  plugins: [tailwindcss(), svelte(), viteSingleFile()],
  build: {
    target: 'es2020',
    outDir: 'dist',
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    reportCompressedSize: true
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:7857' }
  }
});
