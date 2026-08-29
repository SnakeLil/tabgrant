import { spawnSync } from "node:child_process";

const [baseCommit, headCommit] = process.argv.slice(2);
const commitPattern = /^[0-9a-f]{40}$/;

if (!commitPattern.test(baseCommit ?? "") || !commitPattern.test(headCommit ?? "")) {
  fail("usage: node scripts/check-dco.mjs <40-character-base-sha> <40-character-head-sha>");
}

for (const commit of [baseCommit, headCommit]) {
  runGit(["cat-file", "-e", `${commit}^{commit}`]);
}

const commits = runGit(["rev-list", "--reverse", `${baseCommit}..${headCommit}`])
  .trim()
  .split("\n")
  .filter(Boolean);

if (commits.length === 0) {
  fail("the pull request contains no commits to check");
}

const signoffPattern = /^Signed-off-by:\s+\S(?:.*\S)?\s+<[^<>\s]+@[^<>\s]+>\s*$/m;
const failures = [];

for (const commit of commits) {
  const message = runGit(["show", "--no-patch", "--format=%B", commit]);
  if (!signoffPattern.test(message)) {
    const subject = runGit(["show", "--no-patch", "--format=%s", commit]).trim();
    failures.push(`${commit} ${subject}`);
  }
}

if (failures.length > 0) {
  process.stderr.write(
    [
      "DCO check failed. Every pull-request commit must contain a line in this form:",
      "",
      "  Signed-off-by: Name <email@example.com>",
      "",
      "Missing sign-off:",
      ...failures.map((failure) => `  - ${failure}`),
      "",
      "Use `git commit -s` for new commits. Amend and rebase existing commits before pushing.",
      "",
    ].join("\n"),
  );
  process.exit(1);
}

process.stdout.write(`DCO check passed for ${commits.length} commit(s).\n`);

function runGit(args) {
  const result = spawnSync("git", args, {
    cwd: process.cwd(),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    fail(`git ${args.join(" ")} failed: ${(result.stderr || result.stdout).trim()}`);
  }
  return result.stdout;
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
