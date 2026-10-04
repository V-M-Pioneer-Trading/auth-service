/**
 * @file Go's `time.Parse(time.RFC3339, s)` and `Time.Format(time.RFC3339)`, as the Go service used them for the
 * credential row's dates (src/db/credential.go) and the status answer (src/api/routes.go).
 *
 * What is kept is what Go keeps: the UTC offset a date arrived with (`Z` or `+02:00`), not the instant alone;
 * fractional seconds are accepted and dropped; an offset of zero is written `Z`. What Go refuses is refused (a
 * month of 13, a 30th of February, a second of 60). What the general parser accepts that the strict one would
 * not is accepted too (a one-digit hour, a comma before the fraction, an offset of 25:00), because
 * `time.Parse` falls back to it.
 *
 * Only whole milliseconds are kept of a fraction: nothing here compares closer than that.
 */

export interface GoTime {
  /** Milliseconds since the Unix epoch. */
  readonly ms: number;
  /** The offset the date carried, in minutes (Go keeps it in a fixed zone). */
  readonly offsetMinutes: number;
  /** The wall clock the date carried, which is what Go formats from. */
  readonly year: number;
  readonly month: number;
  readonly day: number;
  readonly hour: number;
  readonly minute: number;
  readonly second: number;
}

/** Go's zero `time.Time`, 0001-01-01T00:00:00Z, in milliseconds since the epoch. */
export const ZERO_TIME_MS = -62135596800000;

/** Go's `Time.IsZero`: the instant, whatever the zone. */
export const isZeroTime = (t: GoTime | null): boolean => t === null || t.ms === ZERO_TIME_MS;

const isDigit = (s: string, i: number): boolean => i < s.length && s.charCodeAt(i) >= 0x30 && s.charCodeAt(i) <= 0x39;

const daysIn = (month: number, year: number): number => {
  if (month === 2) return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0 ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
};

/** Go's getnum: one or two digits, or exactly two when `fixed`. */
function getNum(s: string, at: number, fixed: boolean): { value: number; next: number } | null {
  if (!isDigit(s, at)) return null;
  if (!isDigit(s, at + 1)) return fixed ? null : { value: s.charCodeAt(at) - 0x30, next: at + 1 };
  return { value: (s.charCodeAt(at) - 0x30) * 10 + (s.charCodeAt(at + 1) - 0x30), next: at + 2 };
}

/** `time.Parse(time.RFC3339, s)`; null where Go returns an error (and where it returns the zero Time for one). */
export function parseRfc3339(s: string): GoTime | null {
  if (s.length < 4 || ![0, 1, 2, 3].every((i) => isDigit(s, i))) return null;
  const year = Number(s.slice(0, 4));
  let i = 4;
  const literal = (c: string): boolean => {
    if (s[i] !== c) return false;
    i++;
    return true;
  };
  if (!literal("-")) return null;
  const month = getNum(s, i, true);
  if (month === null || month.value < 1 || month.value > 12) return null;
  i = month.next;
  if (!literal("-")) return null;
  const day = getNum(s, i, true);
  if (day === null) return null;
  i = day.next;
  if (!literal("T")) return null;
  const hour = getNum(s, i, false);
  if (hour === null || hour.value > 23) return null;
  i = hour.next;
  if (!literal(":")) return null;
  const minute = getNum(s, i, true);
  if (minute === null || minute.value > 59) return null;
  i = minute.next;
  if (!literal(":")) return null;
  const second = getNum(s, i, true);
  if (second === null || second.value > 59) return null;
  i = second.next;
  // A fraction the layout does not mention is accepted after the seconds, with a period or a comma.
  let millis = 0;
  if (s.length - i >= 2 && (s[i] === "." || s[i] === ",") && isDigit(s, i + 1)) {
    let n = i + 2;
    while (isDigit(s, n)) n++;
    millis = Number((s.slice(i + 1, n) + "000").slice(0, 3));
    i = n;
  }
  // The zone: Z, or a sign and hh:mm. Go 1.22 range-checks neither the hour nor the minute (+25:00 and +23:61 parse), and
  // later versions that do refuse them are not what the image builds with.
  let offsetMinutes = 0;
  if (s[i] === "Z") {
    i++;
  } else {
    if (s.length - i < 6 || s[i + 3] !== ":") return null;
    const sign = s[i];
    if (sign !== "+" && sign !== "-") return null;
    const hh = getNum(s, i + 1, true);
    const mm = getNum(s, i + 4, true);
    if (hh === null || mm === null) return null;
    offsetMinutes = (sign === "-" ? -1 : 1) * (hh.value * 60 + mm.value);
    i += 6;
  }
  if (i !== s.length) return null;
  if (day.value < 1 || day.value > daysIn(month.value, year)) return null;

  const date = new Date(0);
  date.setUTCFullYear(year, month.value - 1, day.value);
  date.setUTCHours(hour.value, minute.value, second.value, millis);
  return {
    ms: date.getTime() - offsetMinutes * 60_000,
    offsetMinutes,
    year,
    month: month.value,
    day: day.value,
    hour: hour.value,
    minute: minute.value,
    second: second.value,
  };
}

const pad = (n: number, width: number): string => String(n).padStart(width, "0");

/** `Time.Format(time.RFC3339)`: the wall clock the date arrived with, no fraction, `Z` for an offset of zero. */
export function formatRfc3339(t: GoTime): string {
  const wall = `${pad(t.year, 4)}-${pad(t.month, 2)}-${pad(t.day, 2)}T${pad(t.hour, 2)}:${pad(t.minute, 2)}:${pad(t.second, 2)}`;
  if (t.offsetMinutes === 0) return `${wall}Z`;
  const abs = Math.abs(t.offsetMinutes);
  return `${wall}${t.offsetMinutes < 0 ? "-" : "+"}${pad(Math.floor(abs / 60), 2)}:${pad(abs % 60, 2)}`;
}
