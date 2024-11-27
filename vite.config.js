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
            "@": path.resolve(__dirname, "./src"),
        },
    },
    build: {
        outDir: path.resolve(__dirname, "public/build"), // Output directory for production files
        emptyOutDir: true, // Ensure old build files are removed
    },
});

// export default defineConfig({
//     plugins: [
//         react(),
//     ],
//     resolve: {
//         alias: {
//             '@': path.resolve(__dirname, './resources/js/src'),
//         },
//     },
//     build: {
//         rollupOptions: {
//             input: 'resources/js/src/main.tsx', // Correct entry point for your React project
//         },
//         outDir: './public/build', // Adjust this based on where you want the build files
//         emptyOutDir: true, // Ensure the output directory is cleared before building
//     },
// });


