import { resolve } from "path";
import { defineConfig } from "vitest/config";
import dts from "vite-plugin-dts";

// Check if we're in production mode
const isProd = process.env.NODE_ENV === "production";

// https://vitejs.dev/guide/build.html#library-mode
export default defineConfig({
  test: {
    setupFiles: ["./vitest.setup.ts"],
  },
  build: {
    lib: {
      entry: {
        "ecies/index": resolve(__dirname, "src/ecies/index.ts"),
        "webcrypto/index": resolve(__dirname, "src/webcrypto/index.ts"),
        "kdf/index": resolve(__dirname, "src/kdf/index.ts"),
        "utils/index": resolve(__dirname, "src/utils/index.ts"),
        "argon/index": resolve(__dirname, "src/argon/index.ts"),
        "nacl/index": resolve(__dirname, "src/nacl/index.ts"),
      },
      name: "@fileverse/crypto",
      formats: ["es", "cjs"],
    },

    minify: isProd ? "terser" : false,
    terserOptions: isProd
      ? {
          compress: {
            drop_console: true,
            drop_debugger: true,
            pure_funcs: ["console.log", "console.info", "console.debug"],
            passes: 2,
          },
          mangle: {
            properties: false,
          },
          format: {
            comments: false,
          },
        }
      : undefined,
    sourcemap: !isProd,
    outDir: "dist",
    chunkSizeWarningLimit: 100,
    rollupOptions: {
      external: [
        "crypto",
        "path",
        "fs",
        "os",
        "util",
        "buffer",
        "process",
        "@peculiar/webcrypto",
        "@noble/ciphers",
        "@noble/curves",
        "@noble/hashes",
        "js-base64",
        /^@noble\/ciphers\/.*/,
        /^@noble\/curves\/.*/,
        /^@noble\/hashes\/.*/,
      ],
      output: [
        {
          format: "es",
          dir: "dist",
          preserveModules: true,
          preserveModulesRoot: "src",
          entryFileNames: "[name].js",
          compact: true,
          sourcemap: !isProd,
        },
        {
          format: "cjs",
          dir: "dist",
          preserveModules: true,
          preserveModulesRoot: "src",
          entryFileNames: "[name].cjs",
          compact: true,
          sourcemap: !isProd,
        },
      ],

      treeshake: {
        moduleSideEffects: false,
        annotations: true,
        tryCatchDeoptimization: false,
        propertyReadSideEffects: false,
      },
    },
  },
  plugins: [
    dts({
      outDir: "dist",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "src/**/__tests__/**"],
    }),
  ],
});
