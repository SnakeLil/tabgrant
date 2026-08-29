import { build } from "esbuild";
import { cp, mkdir, readFile, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = join(packageRoot, "src");
const outputRoot = join(packageRoot, "dist");

const manifest = JSON.parse(await readFile(join(sourceRoot, "manifest.json"), "utf8"));
const allowedPermissions = ["activeTab", "nativeMessaging", "scripting", "storage"];
const actualPermissions = [...(manifest.permissions ?? [])].sort();
if (JSON.stringify(actualPermissions) !== JSON.stringify(allowedPermissions)) {
  throw new Error(`Manifest permissions must be exactly: ${allowedPermissions.join(", ")}`);
}
for (const forbiddenKey of ["host_permissions", "optional_host_permissions", "content_scripts"]) {
  if (forbiddenKey in manifest) throw new Error(`Manifest must not declare ${forbiddenKey}.`);
}

await rm(outputRoot, { recursive: true, force: true });
await mkdir(outputRoot, { recursive: true });

await Promise.all([
  build({
    entryPoints: [join(sourceRoot, "service-worker.ts")],
    outfile: join(outputRoot, "service-worker.js"),
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "chrome105",
    sourcemap: true,
  }),
  build({
    entryPoints: [join(sourceRoot, "content-bridge.ts")],
    outfile: join(outputRoot, "content-bridge.js"),
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "chrome105",
    sourcemap: true,
  }),
  build({
    entryPoints: [join(sourceRoot, "popup.ts")],
    outfile: join(outputRoot, "popup.js"),
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "chrome105",
    sourcemap: true,
  }),
  cp(join(sourceRoot, "manifest.json"), join(outputRoot, "manifest.json")),
  cp(join(sourceRoot, "popup.html"), join(outputRoot, "popup.html")),
  cp(join(sourceRoot, "popup.css"), join(outputRoot, "popup.css")),
]);

console.log(`Built TabGrant MV3 extension in ${outputRoot}`);
