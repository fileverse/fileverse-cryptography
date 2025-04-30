import { resolve } from "path";
import { defineConfig } from "vite";
import dts from "vite-plugin-dts";

// https://vitejs.dev/guide/build.html#library-mode
export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "FileverseCrypto", // Change this to your library's name (used for UMD builds)
      fileName: (format) => `index.${format}.js`, // Output file names based on format
      formats: ["es", "cjs", "umd"], // Generate ES, CJS, and UMD formats
    },
    sourcemap: true,
    // Optimize for production, consider externalizing peer dependencies if any
    // rollupOptions: {
    //   external: [], // e.g., ['react', 'react-dom']
    //   output: {
    //     globals: {} // e.g., { react: 'React', 'react-dom': 'ReactDOM' }
    //   }
    // }
  },
  plugins: [
    dts({
      // Generate declaration files
      insertTypesEntry: true, // Create a single index.d.ts entry file
    }),
  ],
});
