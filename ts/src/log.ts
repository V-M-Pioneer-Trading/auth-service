/**
 * @file The log, as Go's `log.Default()` writes it: stderr, one line, `2006/01/02 15:04:05 ` in front.
 * What a line may hold is the caller's business; see CLAUDE.md "Logging".
 */

export type Logger = (line: string) => void;

const pad = (n: number): string => String(n).padStart(2, "0");

export function timestamp(date: Date): string {
  const day = `${String(date.getFullYear())}/${pad(date.getMonth() + 1)}/${pad(date.getDate())}`;
  return `${day} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export const stderrLog: Logger = (line) => {
  process.stderr.write(`${timestamp(new Date())} ${line}\n`);
};

/** A log line's text with control characters made visible, so a request path cannot forge a line. */
export const visible = (text: string): string => text.replace(/[\u0000-\u001f\u007f]/g, (c) => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0"));
