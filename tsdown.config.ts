import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['./index.ts'],
  format: 'esm',
  outDir: './build',
})
