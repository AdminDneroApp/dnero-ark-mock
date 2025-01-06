import { build } from "esbuild";

build({
    entryPoints: ["index.js"], // Your app's entry point
    bundle: true,              // Bundle all dependencies
    platform: "node",          // Target Node.js environment
    target: "node14",          // Target Node.js version
    outdir: "dist",            // Output directory
    minify: true,              // Minify the output
}).catch(() => process.exit(1));
