import esbuild from "esbuild";

esbuild
  .build({
    format: "esm", // Output as ES module
    entryPoints: ["./calculate_recovery_id.js"], // Your entry file (adjust path)
    bundle: true, // Enable bundling
    outdir: "src/_utils", // Output directory
    platform: "node", // Adjust for Node.js if necessary
    external: ["node_modules"], // Exclude external node_modules
    treeShaking: true, // Optimize tree shaking to remove unused code
    minify: true, // Enable basic minification
    minifySyntax: true, // Minify syntax (remove unnecessary characters)
    minifyWhitespace: true, // Minify whitespace (remove unnecessary spaces and newlines)
    minifyIdentifiers: true, // Minify identifiers (mangle variable names)
  })
  .catch(() => process.exit(1));
