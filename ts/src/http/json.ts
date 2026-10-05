/**
 * @file Go's writeJSON: `Content-Type: application/json` with no charset and a trailing newline. Express' res.json
 * (which tsoa's generated routes call) adds `; charset=utf-8`, which the contract compares. Installed per response.
 */

import type { NextFunction, Request, RequestHandler, Response } from "express";

export const goJson: RequestHandler = (_req: Request, res: Response, next: NextFunction) => {
  res.json = ((body: unknown) => {
    // The caller is gone, or the answer is out already: nothing to write.
    if (res.writableEnded || res.destroyed) return res;
    res.setHeader("Content-Type", "application/json");
    res.end(`${JSON.stringify(body)}\n`);
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
