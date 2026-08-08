import { defineConfig } from 'vitest/config'

export default defineConfig({
  build: {
    cssCodeSplit: true,
    lib: {
      entry: {
        index: 'src/index.ts',
        react: 'src/react.ts',
      },
      formats: ['es'],
    },
    rollupOptions: {
      external: ['lit', '@lit/react', 'react'],
      output: {
        entryFileNames: '[name].js',
        assetFileNames: (assetInfo) =>
          assetInfo.names?.some((name) => name.endsWith('.css')) === true
            ? 'theme.css'
            : 'assets/[name]-[hash][extname]',
      },
    },
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
  },
})
