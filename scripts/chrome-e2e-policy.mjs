export function resolveChromeE2EPolicy(argv, environment = process.env, operatingSystem) {
  const [mode, ...flags] = argv;
  if (
    (mode !== "--ci" && mode !== "--manual") ||
    flags.some((flag) => flag !== "--allow-no-sandbox")
  ) {
    throw new Error(
      "Chrome E2E requires --ci or --manual, optionally followed by --allow-no-sandbox.",
    );
  }
  if (new Set(flags).size !== flags.length) {
    throw new Error("Chrome E2E flags must not be repeated.");
  }

  const allowNoSandbox = flags.includes("--allow-no-sandbox");
  if (
    allowNoSandbox &&
    (mode !== "--ci" || operatingSystem !== "linux" || environment.CI !== "true")
  ) {
    throw new Error(
      "--allow-no-sandbox is restricted to explicit Linux CI runs with a disposable profile.",
    );
  }

  return {
    mode,
    manualUserPresence: mode === "--manual",
    chromeSandboxArgs: allowNoSandbox ? ["--no-sandbox"] : [],
    linuxCiNoSandbox: allowNoSandbox,
  };
}
