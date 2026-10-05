/**
 * @file Go's string rules where the Go service's behaviour depends on them.
 */

/** Go's unicode.IsSpace. JavaScript's trim() differs: it strips U+FEFF and keeps U+0085. */
const isGoSpace = (code: number): boolean =>
  (code >= 0x09 && code <= 0x0d) ||
  code === 0x20 ||
  code === 0x85 ||
  code === 0xa0 ||
  code === 0x1680 ||
  (code >= 0x2000 && code <= 0x200a) ||
  code === 0x2028 ||
  code === 0x2029 ||
  code === 0x202f ||
  code === 0x205f ||
  code === 0x3000;

/** Go's strings.TrimSpace. */
export function goTrimSpace(s: string): string {
  const points = Array.from(s);
  let start = 0;
  let end = points.length;
  while (start < end && isGoSpace((points[start] ?? "").codePointAt(0) ?? -1)) start++;
  while (end > start && isGoSpace((points[end - 1] ?? "").codePointAt(0) ?? -1)) end--;
  return points.slice(start, end).join("");
}

/** Go's getEnv helper (src/db/db.go): unset and empty both mean "use the fallback". */
export function getEnv(env: Record<string, string | undefined>, key: string, fallback: string): string {
  const value = env[key];
  return value === undefined || value === "" ? fallback : value;
}
