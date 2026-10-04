/**
 * @file Reading a request body the way Go's server hands it to a handler: through `http.MaxBytesReader(w, r.Body,
 * limit)`, read only when the handler reads. Ported from agent-service's http/body.ts.
 *
 *  - `Expect: 100-continue` is answered when the handler starts reading, never before (server.ts sends none by
 *    itself), so a caller refused before the read (a wrong secret, a body that is not a form) never uploads. Only for
 *    HTTP/1.1 and later, and only when a body is announced: Go's server sends no 100 for HTTP/1.0 or Content-Length 0.
 *  - The cap is on the bytes that arrive, chunked or not; Content-Length is never trusted. `limit` bytes are accepted,
 *    one more is "exceeded" and the rest is not read: the connection is closed once the answer is out (server.ts
 *    closeWhenBodyUnread), as Go closes it after MaxBytesReader trips.
 *  - A caller who hangs up before the body is in is `CallerGone`: nobody is left to answer.
 */
import type { IncomingMessage, ServerResponse } from "node:http";

/** The caller hung up before its request was read: nobody is left to answer. */
export class CallerGone extends Error {
  constructor() {
    super("the caller hung up");
    this.name = "CallerGone";
  }
}

export interface BodyRead {
  /** At most `limit` bytes. */
  readonly bytes: Buffer;
  /** True when the caller sent more than `limit`; the rest is not read. */
  readonly exceeded: boolean;
}

/** Whether the caller waits for a 100 before it sends the body: Node's own test (any other Expect is a 417 before routing). */
function expectsContinue(req: IncomingMessage): boolean {
  return /(?:^|\W)100-continue(?:$|\W)/i.test(req.headers.expect ?? "");
}

/** Go's ContentLength != 0: a body is announced by a non-zero length or by chunking. */
function bodyAnnounced(req: IncomingMessage): boolean {
  const length = req.headers["content-length"];
  return req.headers["transfer-encoding"] !== undefined || (length !== undefined && !/^0+$/.test(length));
}

export function readBody(req: IncomingMessage, limit: number): Promise<BodyRead> {
  const res = (req as { res?: ServerResponse }).res;
  const http11 = req.httpVersionMajor > 1 || (req.httpVersionMajor === 1 && req.httpVersionMinor >= 1);
  if (http11 && expectsContinue(req) && bodyAnnounced(req) && res !== undefined && !res.headersSent) res.writeContinue();
  return new Promise<BodyRead>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const settle = (): boolean => {
      if (settled) return false;
      settled = true;
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("close", onClose);
      req.off("error", onError);
      return true;
    };
    function onData(chunk: Buffer): void {
      size += chunk.length;
      chunks.push(chunk);
      if (size <= limit || !settle()) return;
      req.pause();
      resolve({ bytes: Buffer.concat(chunks).subarray(0, limit), exceeded: true });
    }
    function onEnd(): void {
      if (settle()) resolve({ bytes: Buffer.concat(chunks), exceeded: false });
    }
    function onClose(): void {
      // 'close' after 'end' is normal; before it, the caller is gone.
      if (settle()) reject(new CallerGone());
    }
    function onError(): void {
      if (settle()) reject(new CallerGone());
    }
    req.on("data", onData);
    req.on("end", onEnd);
    req.on("close", onClose);
    req.on("error", onError);
    // A request whose body has already been read to the end (nothing was announced) still ends here.
    if (req.complete && req.readableEnded) onEnd();
  });
}
