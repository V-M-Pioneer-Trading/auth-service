// Runs the contract suite (contract/) against the TypeScript service image, whole and
// unfiltered, and judges it against contract-skip.txt.
//
//   CONTRACT_IMAGE=auth-service:contract node scripts/run-contract.cjs     (from the repository root)
//
// The suite is not modified and no case is removed from the run. Every leaf test's
// full name (describe names and test name, joined by single spaces, which is what
// `node --test --test-skip-pattern` matches) is compared with the skip patterns:
//
//   * a case NOT on the list must pass: any failure is a defect;
//   * a case on the list may fail (its route is not ported), but must not pass,
//     except the ones named in contract-skip-passing.txt, which pass vacuously;
//     so a pattern that is too broad, or stale after a route was ported, fails;
//   * a pattern that matches no case fails;
//   * a suite that failed for its own reason (an after hook that threw, a describe
//     body that threw) fails unless it is on the list; code that threw outside any
//     test (an uncaught exception after a test ended) always fails; a non-zero exit
//     of the suite with no failed case to explain it fails;
//   * the measured numbers must equal contract-skip.expected: the suite's size,
//     how many cases the list covers, how many pass, how many the suite itself
//     skips. The list can only change together with that file.
//
// Environment: CONTRACT_IMAGE, the image to run (required: the suite is black-box).
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { pathToFileURL } = require("url");

const root = path.join(__dirname, ".."); // the repository root
const contractDir = [path.join(root, "contract")].find((d) => fs.existsSync(path.join(d, "tests")));

const readLines = (file) =>
  fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== "" && !l.startsWith("#"));

/**
 * Pure: the verdict on a run.
 * `events` are the reporter's lines, `status` the suite process's exit code,
 * `expected` the parsed contract-skip.expected.
 */
function judge(events, patterns, vacuous, expected, status = 1) {
  const regexes = patterns.map((p) => new RegExp(p));
  const problems = [];
  const counts = { suite: 0, listed: 0, pass: 0, dynamicSkips: 0 };
  const vacuousSeen = new Set();
  const used = new Set();
  // node:test skips a test whose own name matches, or any ancestor suite's.
  const isListed = (pathNames) => {
    const prefixes = pathNames.map((_, i) => pathNames.slice(0, i + 1).join(" "));
    return regexes.reduce((any, re, i) => {
      const hit = prefixes.some((p) => re.test(p));
      if (hit) used.add(i);
      return any || hit;
    }, false);
  };
  let failures = 0;
  for (const e of events) {
    if (e.kind === "diagnostic") {
      problems.push(`code threw outside any test: ${e.message}`);
      continue;
    }
    if (e.kind === "suite") {
      if (!isListed(e.path)) problems.push(`suite failed for its own reason (${e.failureType}) and is not on the skip list: ${e.path.join(" ")}`);
      failures++;
      continue;
    }
    counts.suite++;
    const name = e.path.join(" ");
    const listed = isListed(e.path);
    if (e.outcome === "skip") {
      counts.dynamicSkips++;
      continue;
    }
    if (e.outcome === "fail") failures++;
    if (listed) {
      counts.listed++;
      if (e.outcome === "pass") {
        if (vacuous.has(name)) vacuousSeen.add(name);
        else problems.push(`on the skip list but passing (a stale or too broad pattern?): ${name}`);
      }
    } else if (e.outcome === "pass") {
      counts.pass++;
    } else {
      problems.push(`FAILED and not on the skip list: ${name}`);
    }
  }
  patterns.forEach((p, i) => {
    if (!used.has(i)) problems.push(`skip pattern matches no case: ${p}`);
  });
  for (const v of vacuous) if (!vacuousSeen.has(v)) problems.push(`contract-skip-passing.txt names a case that does not pass on the list: ${v}`);
  if (status !== 0 && failures === 0) problems.push(`the suite exited with status ${status} but no case or suite failed: something went wrong outside the tests`);
  const want = { suite: expected.suite, listed: expected.skipped, pass: expected.pass, dynamicSkips: expected["dynamic-skips"] };
  for (const key of Object.keys(want)) {
    if (counts[key] !== want[key]) problems.push(`measured ${key}=${counts[key]}, contract-skip.expected says ${want[key]}`);
  }
  return { problems, counts };
}

/** Runs `node --test contract.test.ts` in dir with the judging reporter; returns what happened. */
function runSuite(dir, env = process.env) {
  const resultsFile = path.join(os.tmpdir(), `contract-results-${process.pid}-${Date.now()}.jsonl`);
  const args = [
    "--test",
    "--test-timeout=120000",
    "--test-reporter=spec",
    "--test-reporter-destination=stdout",
    `--test-reporter=${pathToFileURL(path.join(__dirname, "contract-reporter.cjs")).href}`,
    `--test-reporter-destination=${resultsFile}`,
    "tests/*.test.ts",
  ];
  const run = spawnSync(process.execPath, args, { cwd: dir, env, encoding: "utf8", maxBuffer: 512 << 20 });
  const events = fs.existsSync(resultsFile)
    ? fs.readFileSync(resultsFile, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l))
    : [];
  fs.rmSync(resultsFile, { force: true });
  return { status: run.status ?? 1, output: `${run.stdout ?? ""}${run.stderr ?? ""}`, events };
}

module.exports = { judge, runSuite, readLines };

if (require.main === module) {
  const patterns = readLines(path.join(root, "contract-skip.txt"));
  const vacuous = new Set(readLines(path.join(root, "contract-skip-passing.txt")));
  const expected = Object.fromEntries(readLines(path.join(root, "contract-skip.expected")).map((l) => l.split("=").map((s) => s.trim())));
  for (const key of ["suite", "skipped", "pass", "dynamic-skips"]) {
    if (!/^[0-9]+$/.test(expected[key] ?? "")) throw new Error(`contract-skip.expected: ${key}=<number> is missing`);
    expected[key] = Number(expected[key]);
  }
  for (const p of patterns) new RegExp(p); // a pattern that does not compile fails here

  const env = { ...process.env };
  if (!env.CONTRACT_IMAGE) throw new Error("set CONTRACT_IMAGE to the image under test");
  if (contractDir === undefined) throw new Error("the contract suite (contract/tests) was not found");
  const { status, output, events } = runSuite(contractDir, env);
  // The whole spec output is long and mostly the listed failures; keep the tail.
  process.stdout.write(output.split("\n").slice(-60).join("\n") + "\n");

  const { problems, counts } = judge(events, patterns, vacuous, expected, status);
  console.log(`\ncontract against the TypeScript service: ${counts.pass} pass outside the list, ${counts.listed} of ${counts.suite} cases on the skip list (${patterns.length} patterns), ${counts.dynamicSkips} skipped by the suite`);
  if (events.length === 0) problems.push("no test results were recorded (did the suite start?)");
  if (problems.length > 0) {
    for (const p of problems.slice(0, 40)) console.error(`::error::${p}`);
    if (problems.length > 40) console.error(`::error::... and ${problems.length - 40} more`);
    process.exit(1);
  }
}
