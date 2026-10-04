import fs from "node:fs";
import os from "node:os";
import { createRequire } from "node:module";
import path from "node:path";

type Event =
  | { kind: "test"; path: string[]; outcome: "pass" | "fail" | "skip" }
  | { kind: "suite"; path: string[]; failureType: string }
  | { kind: "diagnostic"; message: string };

const { judge, runSuite } = createRequire(__filename)("../../scripts/run-contract.cjs") as {
  judge: (
    events: Event[],
    patterns: string[],
    vacuous: Set<string>,
    expected: Record<string, number>,
    status?: number,
  ) => { problems: string[]; counts: Record<string, number> };
  runSuite: (dir: string) => { status: number; output: string; events: Event[] };
};

const r = (outcome: "pass" | "fail" | "skip", ...path: string[]): Event => ({ kind: "test", path, outcome });
const expected = { suite: 4, skipped: 2, pass: 2, "dynamic-skips": 0 };
const base = [r("pass", "health", "ok"), r("pass", "routing", "404"), r("fail", "ships", "GET a"), r("fail", "ships", "GET b")];
const patterns = ["^ships$"];

describe("the contract skip-list judge", () => {
  it("accepts: unlisted cases pass, listed cases fail, the numbers match", () => {
    expect(judge(base, patterns, new Set(), expected).problems).toEqual([]);
  });

  it("a failure outside the list is a defect", () => {
    const out = judge([r("pass", "health", "ok"), r("fail", "routing", "404"), ...base.slice(2)], patterns, new Set(), expected);
    expect(out.problems.join("\n")).toMatch(/FAILED and not on the skip list: routing 404/);
  });

  it("a listed case that passes is a stale or too broad pattern, unless it is named as vacuous", () => {
    const passing = [...base.slice(0, 3), r("pass", "ships", "GET b")];
    expect(judge(passing, patterns, new Set(), expected).problems.join("\n")).toMatch(/on the skip list but passing.*ships GET b/);
    expect(judge(passing, patterns, new Set(["ships GET b"]), expected).problems).toEqual([]);
  });

  it("a pattern that is too broad swallows a passing case and changes the counts", () => {
    const out = judge(base, ["^(ships|routing)$"], new Set(), expected);
    expect(out.problems.join("\n")).toMatch(/on the skip list but passing.*routing 404/);
    expect(out.problems.join("\n")).toMatch(/measured listed=3/);
  });

  it("a pattern that matches nothing, and a vacuous name that does not pass, are reported", () => {
    const out = judge(base, [...patterns, "^nothing$"], new Set(["ghost"]), expected);
    expect(out.problems.join("\n")).toMatch(/skip pattern matches no case: \^nothing\$/);
    expect(out.problems.join("\n")).toMatch(/names a case that does not pass on the list: ghost/);
  });

  it("matches a pattern against a suite name as node:test does, and a '/' in a pattern is fine", () => {
    const out = judge([r("fail", "POST /ships/{id}", "bad")], ["^POST /ships/\\{id\\}$"], new Set(), { suite: 1, skipped: 1, pass: 0, "dynamic-skips": 0 }, 1);
    expect(out.problems).toEqual([]);
  });

  it("the totals are checked against the committed numbers", () => {
    const out = judge([...base, r("pass", "extra", "one")], patterns, new Set(), expected);
    expect(out.problems.join("\n")).toMatch(/measured suite=5/);
  });

  it("a suite that failed for its own reason is a problem unless it is listed", () => {
    const hook: Event = { kind: "suite", path: ["routing"], failureType: "hookFailed" };
    expect(judge([...base, hook], patterns, new Set(), expected).problems.join("\n")).toMatch(/suite failed for its own reason \(hookFailed\).*routing/);
    expect(judge([...base, { kind: "suite", path: ["ships"], failureType: "hookFailed" }], patterns, new Set(), expected).problems).toEqual([]);
  });

  it("code that threw outside any test is always a problem", () => {
    const stray: Event = { kind: "diagnostic", message: "Error: late (uncaughtException)" };
    expect(judge([...base, stray], patterns, new Set(), expected).problems.join("\n")).toMatch(/code threw outside any test/);
  });

  it("a non-zero exit with no failed case to explain it is a problem; with one, it is not", () => {
    const green = [r("pass", "health", "ok")];
    const want = { suite: 1, skipped: 0, pass: 1, "dynamic-skips": 0 };
    expect(judge(green, [], new Set(), want, 0).problems).toEqual([]);
    expect(judge(green, [], new Set(), want, 7).problems.join("\n")).toMatch(/exited with status 7 but no case or suite failed/);
    expect(judge(base, patterns, new Set(), expected, 1).problems).toEqual([]);
  });
});

// The same rules, end to end: a real node:test run of a small suite through the real reporter.
describe("the judge on a real run of a mock suite", () => {
  const dirs: string[] = [];
  afterAll(() => { dirs.forEach((d) => { fs.rmSync(d, { recursive: true, force: true }); }); });

  function mock(source: string) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mock-contract-"));
    dirs.push(dir);
    fs.mkdirSync(path.join(dir, "tests"));
    fs.writeFileSync(path.join(dir, "tests", "contract.test.ts"), source);
    const run = runSuite(dir);
    const tests = run.events.filter((e) => e.kind === "test").length;
    return { run, judged: judge(run.events, [], new Set(), { suite: tests, skipped: 0, pass: tests, "dynamic-skips": 0 }, run.status) };
  }

  it("a clean suite is clean", () => {
    const { run, judged } = mock(`import { describe, it } from 'node:test';\ndescribe('s', () => { it('a', () => {}); });\n`);
    expect([run.status, judged.problems]).toEqual([0, []]);
  });

  it("an after hook that throws (every test passes) is caught", () => {
    const { judged } = mock(`import { describe, it, after } from 'node:test';\ndescribe('s', () => { it('a', () => {}); after(() => { throw new Error('boom'); }); });\n`);
    expect(judged.problems.join("\n")).toMatch(/suite failed for its own reason \(hookFailed\)/);
  });

  it("a describe body that throws after registering tests is caught", () => {
    const { judged } = mock(`import { describe, it } from 'node:test';\ndescribe('s', () => { it('a', () => {}); throw new Error('body'); });\n`);
    expect(judged.problems.join("\n")).toMatch(/suite failed for its own reason|FAILED and not on the skip list/);
  });

  it("an uncaught exception after a test ended is caught", () => {
    const { judged } = mock(
      `import { describe, it } from 'node:test';\ndescribe('s', () => {\n it('a', () => { setTimeout(() => { throw new Error('late'); }, 30); });\n it('b', async () => { await new Promise((r) => setTimeout(r, 300)); });\n});\n`,
    );
    expect(judged.problems.length).toBeGreaterThan(0);
  });
});
