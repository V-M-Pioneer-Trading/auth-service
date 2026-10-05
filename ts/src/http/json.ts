/**
 * @file Go's writeJSON: `Content-Type: application/json` with no charset and a trailing newline. Express' res.json
 * (which tsoa's generated routes call) adds `; charset=utf-8`, which the contract compares. Installed per response.
 */

import type { NextFunction, Request, RequestHandler, Response } from "express";

const GO_ESCAPES: Record<string, string> = { "<": "\\u003c", ">": "\\u003e", "&": "\\u0026", "\u2028": "\\u2028", "\u2029": "\\u2029" };

/**
 * `json.Marshal`'s bytes for a value JSON.stringify can write: Go escapes `<`, `>` and `&` (HTML-safe) and U+2028 and
 * U+2029 inside strings. Those characters can only stand inside a string in JSON.stringify's output, so replacing them
 * anywhere is replacing them in strings. A lone surrogate (which JSON.stringify writes as `\udXXX`) becomes U+FFFD, as
 * Go's encoder makes invalid UTF-8; no value this service answers holds one.
 */
export function goMarshal(value: unknown): string {
  return JSON.stringify(value)
    .replace(/[<>&\u2028\u2029]/g, (c) => GO_ESCAPES[c] ?? c)
    .replace(/(?<!\\)((?:\\\\)*)\\ud[89a-f][0-9a-f]{2}/g, "$1\\ufffd");
}

export const goJson: RequestHandler = (_req: Request, res: Response, next: NextFunction) => {
  res.json = ((body: unknown) => {
    // The caller is gone, or the answer is out already: nothing to write.
    if (res.writableEnded || res.destroyed) return res;
    res.setHeader("Content-Type", "application/json");
    res.end(`${goMarshal(body)}\n`);
    return res;
  }) as Response["json"];
  next();
};

/**
 * An answer that is a status and a sentence, `http.Error`: thrown from a handler and written by the app's error
 * handler (a 500 from the database). `bytes`, when given, is the sentence as raw bytes (upstream's text passed through
 * to the operator), written in place of `message`.
 */
export class TextAnswer extends Error {
  readonly status: number;
  readonly bytes: Buffer | undefined;
  constructor(status: number, message: string, bytes?: Buffer) {
    super(message);
    this.name = "TextAnswer";
    this.status = status;
    this.bytes = bytes;
  }

  /** What is written before the newline. */
  get body(): string | Buffer {
    return this.bytes ?? this.message;
  }
}

/** net/http's http.Error: text/plain, the message and one newline. */
export function sendText(res: Response, status: number, message: string | Buffer): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(typeof message === "string" ? `${message}\n` : Buffer.concat([message, Buffer.from("\n")]));
}
