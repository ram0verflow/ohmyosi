import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/events": "http://127.0.0.1:7777",
      "/api": "http://127.0.0.1:7777",
      "/icons": "http://127.0.0.1:7777",
      "/favicons": "http://127.0.0.1:7777",
    },
  },
});
