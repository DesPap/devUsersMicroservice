import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import laravel from "laravel-vite-plugin";


export default defineConfig({
    plugins: [
        laravel({
            input: ["resources/js/src/main.tsx"],
            refresh: true, // Automatically refresh the browser during development
        }),
        react(),
    ],
    resolve: {
        alias: {
            "@": path.resolve(__dirname, "resources/js/src"),
        },
    },
    server: {
        host: "0.0.0.0", // Makes the Vite server accessible externally
        // host: "localhost",
        port: 5173, // Match the port with Docker
        strictPort: true, // Ensures the exact port is used
        hmr: {
            host: 'localhost', // This should be the public hostname or IP
            port: 5173, // Match the development server port
        },
        watch: {
            usePolling: true, // Ensure file changes are detected in Docker
        },
    },
    // build: { 
    //     outDir: path.resolve(__dirname, "public/build"), // Output directory for production files. Doesn't affect npm run dev
    //     emptyOutDir: true, // Ensure old build files are removed
    // },
});


