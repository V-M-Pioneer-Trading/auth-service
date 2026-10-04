/**
 * @file The Node floor. node:sqlite is a release candidate from 24.15.0 and experimental before it (decision 23);
 * the image is chosen to be above it, and the process refuses to run below it rather than store the game credential
 * through an API its own runtime calls experimental.
 */

export const MIN_NODE: readonly [number, number] = [24, 15];

/** An error message when `version` ("24.14.0") is below the floor, else undefined. */
export function nodeTooOld(version: string): string | undefined {
  const [major = 0, minor = 0] = version.split(".").map(Number);
  const [wantMajor, wantMinor] = MIN_NODE;
  if (major > wantMajor || (major === wantMajor && minor >= wantMinor)) return undefined;
  return `Node ${version} is too old: node:sqlite is only a release candidate from ${String(wantMajor)}.${String(wantMinor)}.0`;
}
