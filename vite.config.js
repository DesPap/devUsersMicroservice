import { defineConfig } from 'vite';
import laravel from 'laravel-vite-plugin';
import react from '@vitejs/plugin-react';
import path from 'path';

// export default defineConfig({
//     plugins: [
//         laravel({
//             input: ['resources/css/app.css', 'resources/js/app.js'],
//             refresh: true,
//         }),
//     ],
// });

// export default defineConfig({
//     plugins: [laravel(["resources/js/src/main.tsx"]), react()],
//     resolve: {
//         alias: {
//             "@": path.resolve(__dirname, "./src"),
//         },
//     },
// });

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
        port: 5173, // Match the port with Docker
    },
    build: {
        outDir: path.resolve(__dirname, "public/build"), // Output directory for production files
        emptyOutDir: true, // Ensure old build files are removed
    },
});


