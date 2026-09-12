import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// base: "./" makes built asset URLs relative, so the same bundle works both at
// a domain root and under a GitHub Pages subpath (/aegis-saas/) unchanged.
export default defineConfig({
  base: "./",
  plugins: [react()],
  server: { port: 5173 },
});
