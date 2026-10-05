// A node:test reporter that writes one JSON line per event worth judging:
//
//   {"kind":"test",  "path":[describe names..., test name], "outcome":"pass"|"fail"|"skip"}
//   {"kind":"suite", "path":[...], "failureType":"hookFailed"|"testCodeFailure"|...}
//        a suite that failed for a reason of its own (an after hook that threw, a
//        describe body that threw), not merely because a test inside it failed
//   {"kind":"diagnostic", "message":"..."}
//        node's note that code threw outside any test (an uncaught exception after
//        a test ended, an unhandled rejection), which does not fail the test
//
// --test-skip-pattern matches the space-joined path of a test or of any of its
// ancestors, so run-contract.js can say which cases a skip pattern would have
// removed without removing them from the run.
const STRAY = /uncaught ?exception|unhandled ?rejection|asynchronous activity after the test ended/i;

module.exports = async function* (source) {
  const stack = [];
  for await (const event of source) {
    const d = event.data;
    if (event.type === "test:start") {
      stack.length = d.nesting;
      stack[d.nesting] = d.name;
    } else if (event.type === "test:pass" || event.type === "test:fail") {
      const path = [...stack.slice(0, d.nesting), d.name];
      if (d.details?.type === "suite") {
        const failureType = d.details?.error?.failureType;
        if (event.type === "test:fail" && failureType !== "subtestsFailed") {
          yield JSON.stringify({ kind: "suite", path, failureType: failureType ?? "unknown" }) + "\n";
        }
        continue;
      }
      const outcome = event.type === "test:fail" ? "fail" : d.skip !== undefined || d.todo !== undefined ? "skip" : "pass";
      yield JSON.stringify({ kind: "test", path, outcome }) + "\n";
    } else if (event.type === "test:diagnostic" && STRAY.test(String(d.message))) {
      yield JSON.stringify({ kind: "diagnostic", message: String(d.message).slice(0, 300) }) + "\n";
    }
  }
};
