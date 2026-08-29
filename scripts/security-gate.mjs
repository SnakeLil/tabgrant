import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dispatchCdpResponse } from "./cdp-response.mjs";
import { resolveChromeE2EPolicy } from "./chrome-e2e-policy.mjs";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const manifestPath = join(projectRoot, "apps", "extension", "src", "manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const rootPackage = JSON.parse(await readFile(join(projectRoot, "package.json"), "utf8"));

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
const expectedNodeEngine = ">=20.19.0";
if (
  rootPackage.engines?.node !== expectedNodeEngine ||
  brokerPackage.engines?.node !== expectedNodeEngine
) {
  fail(`root and published package Node engines must both be exactly ${expectedNodeEngine}`);
}
const ciWorkflow = await readFile(join(projectRoot, ".github", "workflows", "ci.yml"), "utf8");
if (!ciWorkflow.includes('- "20.19.0"') || ciWorkflow.includes("20.18.0")) {
  fail("CI must exercise the exact Node.js 20.19.0 minimum");
}
for (const [name, version] of Object.entries(brokerPackage.dependencies ?? {})) {
  if (String(version).startsWith("workspace:")) {
    fail(`published package has a workspace runtime dependency: ${name}`);
  }
}
if (brokerPackage.bin?.["tabgrant-native-host"] !== "dist/native-host-entry.js") {
  fail("published package is missing the fixed native-host executable");
}

const regularCiPolicy = resolveChromeE2EPolicy(["--ci"], {}, "linux");
if (regularCiPolicy.chromeSandboxArgs.length !== 0) {
  fail("regular Chrome E2E must preserve the browser sandbox");
}
const linuxCiPolicy = resolveChromeE2EPolicy(
  ["--ci", "--allow-no-sandbox"],
  { CI: "true" },
  "linux",
);
if (
  linuxCiPolicy.chromeSandboxArgs.length !== 1 ||
  linuxCiPolicy.chromeSandboxArgs[0] !== "--no-sandbox" ||
  !linuxCiPolicy.linuxCiNoSandbox
) {
  fail("explicit disposable Linux CI must be the only no-sandbox Chrome policy");
}
for (const [argv, environment, operatingSystem] of [
  [["--manual", "--allow-no-sandbox"], { CI: "true" }, "linux"],
  [["--ci", "--allow-no-sandbox"], {}, "linux"],
  [["--ci", "--allow-no-sandbox"], { CI: "true" }, "darwin"],
]) {
  expectFailure(() => resolveChromeE2EPolicy(argv, environment, operatingSystem));
}
const chromeE2eSource = await readFile(join(projectRoot, "scripts", "chrome-e2e.mjs"), "utf8");
if (chromeE2eSource.includes('"--no-sandbox"')) {
  fail("Chrome E2E must obtain no-sandbox only from the guarded policy module");
}
if (!chromeE2eSource.includes("...e2ePolicy.chromeSandboxArgs")) {
  fail("Chrome E2E must apply the guarded sandbox policy at launch");
}
if (
  !chromeE2eSource.includes(
    "Refusing to disable the Chrome sandbox outside the disposable E2E profile",
  )
) {
  fail("Chrome E2E must verify the disposable profile before disabling the sandbox");
}
if (
  rootPackage.scripts?.["e2e:chrome:ci:linux-no-sandbox"] !==
  "pnpm build && pnpm --filter tabgrant exec tsx ../../scripts/chrome-e2e.mjs --ci --allow-no-sandbox"
) {
  fail("the Linux CI no-sandbox command must remain an explicit guarded E2E invocation");
}
if (
  String(rootPackage.scripts?.["e2e:chrome:ci"]).includes("allow-no-sandbox") ||
  String(rootPackage.scripts?.["e2e:chrome:manual"]).includes("allow-no-sandbox")
) {
  fail("default and manual Chrome E2E commands must preserve the sandbox");
}
if (!ciWorkflow.includes("pnpm e2e:chrome:ci:linux-no-sandbox")) {
  fail("Linux Chrome CI must opt into the dedicated disposable-profile command");
}

const dispatchedMessages = [];
const pendingCdpResponses = new Map([
  [7, (message) => dispatchedMessages.push(message)],
  [8, "not-a-function"],
]);
for (const serialized of [
  "not-json",
  "null",
  "[]",
  '{"id":"7"}',
  '{"id":0}',
  '{"id":9007199254740992}',
  '{"id":8}',
  '{"id":9}',
  '{"id":{"toString":"untrusted"}}',
]) {
  if (dispatchCdpResponse(serialized, pendingCdpResponses)) {
    fail("CDP dispatch accepted an invalid, unknown, or non-callable response id");
  }
}
if (
  !dispatchCdpResponse('{"id":7,"result":{"ok":true}}', pendingCdpResponses) ||
  dispatchedMessages.length !== 1 ||
  pendingCdpResponses.has(7) ||
  dispatchCdpResponse('{"id":7,"result":{"ok":true}}', pendingCdpResponses)
) {
  fail("CDP dispatch must invoke a validated pending callback exactly once");
}

process.stdout.write("TabGrant security gate passed.\n");

function fail(message) {
  throw new Error(`Security gate failed: ${message}`);
}

function expectFailure(operation) {
  try {
    operation();
  } catch {
    return;
  }
  fail("Chrome E2E no-sandbox policy accepted a forbidden context");
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
