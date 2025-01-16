import esbuild from "esbuild";

esbuild
  .build({
    entryPoints: ["./_utils/calculate_recovery_id.js"],
    bundle: true,
    outdir: "_utils",
    minify: true,
    platform: "browser",
    sourcemap: false,
    allowOverwrite: true,
    treeShaking: true,
    minifySyntax: true,
    minifyWhitespace: true,
    minifyIdentifiers: true,
    format: "esm",
  })
  .then(() => {
    console.log("JS files in _utils folder minified successfully!");
  })
  .catch((error) => {
    console.error("Error during build:", error);
    process.exit(1);
  });
