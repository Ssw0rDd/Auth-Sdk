import { defineConfig } from 'vitest/config'

export default defineConfig({
  build: {
    lib: {
      entry: {
        index: 'src/index.ts',
        node: 'src/node.ts',
        stores: 'src/stores.ts',
      },
      formats: ['es'],
    },
    rollupOptions: {
      output: { entryFileNames: '[name].js' },
    },
    sourcemap: false,
  },
  test: {
    environment: 'node',
  },
})
