import { nodeTooOld } from "../runtime";

describe("the Node floor (node:sqlite is a release candidate from 24.15.0)", () => {
  it.each(["24.14.0", "24.14.9", "24.0.0", "22.13.0", "23.9.0", "20.0.0"])("refuses %s", (version) => {
    expect(nodeTooOld(version)).toMatch(new RegExp(`Node ${version.replaceAll(".", "\\.")} is too old`));
  });

  it.each(["24.15.0", "24.15.1", "24.21.0", "25.0.0", "26.1.0"])("accepts %s", (version) => {
    expect(nodeTooOld(version)).toBeUndefined();
  });

  it("holds for the Node that runs the tests", () => {
    expect(nodeTooOld(process.versions.node)).toBeUndefined();
  });
});
