import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const manifestPath = join(projectRoot, "apps", "extension", "src", "manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));

const expectedPermissions = ["activeTab", "nativeMessaging", "scripting", "storage"];
const actualPermissions = [...(manifest.permissions ?? [])].sort();
if (JSON.stringify(actualPermissions) !== JSON.stringify([...expectedPermissions].sort())) {
  fail(`manifest permissions must be exactly ${expectedPermissions.join(", ")}`);
}

for (const forbiddenKey of [
  "host_permissions",
  "optional_host_permissions",
  "content_scripts",
  "externally_connectable",
]) {
  if (forbiddenKey in manifest) fail(`manifest must not contain ${forbiddenKey}`);
}

const productionFiles = (
  await Promise.all([
    sourceFiles("apps/extension/src"),
    sourceFiles("apps/extension/scripts"),
    sourceFiles("apps/broker/src"),
  ])
).flat();
const forbiddenPatterns = [
  [/chrome\.debugger\b/, "chrome.debugger"],
  [/chrome\.cookies\b/, "chrome.cookies"],
  [/document\.cookie\b/, "document.cookie"],
  [/remote-debugging-(?:port|pipe)/, "remote debugging"],
  [/\beval\s*\(/, "eval"],
  [/\bnew\s+Function\s*\(/, "new Function"],
];

const productionSources = new Map();
for (const relativePath of productionFiles) {
  const source = await readFile(join(projectRoot, relativePath), "utf8");
  productionSources.set(relativePath, source);
  for (const [pattern, label] of forbiddenPatterns) {
    if (pattern.test(source)) fail(`${relativePath} contains forbidden authority: ${label}`);
  }
}

const authSource = productionSources.get("apps/broker/src/auth.ts");
const cliSource = productionSources.get("apps/broker/src/cli.ts");
const daemonSource = productionSources.get("apps/broker/src/daemon.ts");
if (authSource.includes("process.env")) {
  fail("browser pairing approval must not depend on environment variables");
}
if (/case\s+["']pair["']|tabgrant\s+pair\b/i.test(cliSource)) {
  fail("browser pairing must not expose a CLI approval command");
}
if (
  !/pairingApprover:\s*PairingApprover\s*=\s*createSystemPairingApprover\(\)/.test(daemonSource)
) {
  fail("the production broker must default to the system user-presence pairing approver");
}
const combinedProductionSource = [...productionSources.values()].join("\n");
for (const [pattern, label] of [
  [/pairing[-_ ]?proposal/i, "pairing proposal queue"],
  [/auto[-_ ]?approve/i, "automatic pairing approval"],
  [/TABGRANT_[A-Z0-9_]*PAIR[A-Z0-9_]*(?:APPROVE|ALLOW)/, "pairing approval environment bypass"],
]) {
  if (pattern.test(combinedProductionSource)) fail(`production source contains ${label}`);
}

const brokerPackage = JSON.parse(
  await readFile(join(projectRoot, "apps", "broker", "package.json"), "utf8"),
);
for (const [name, version] of Object.entries(brokerPackage.dependencies ?? {})) {
  if (String(version).startsWith("workspace:")) {
    fail(`published package has a workspace runtime dependency: ${name}`);
  }
}
if (brokerPackage.bin?.["tabgrant-native-host"] !== "dist/native-host-entry.js") {
  fail("published package is missing the fixed native-host executable");
}

process.stdout.write("TabGrant security gate passed.\n");

function fail(message) {
  throw new Error(`Security gate failed: ${message}`);
}

async function sourceFiles(relativeDirectory) {
  const entries = await readdir(join(projectRoot, relativeDirectory), { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const relativePath = `${relativeDirectory}/${entry.name}`;
    if (entry.isDirectory()) {
      files.push(...(await sourceFiles(relativePath)));
    } else if (
      entry.isFile() &&
      !/\.test\.[cm]?[jt]s$/.test(entry.name) &&
      /\.(?:js|mjs|cjs|ts)$/.test(entry.name)
    ) {
      files.push(relativePath);
    }
  }
  return files.sort();
}
