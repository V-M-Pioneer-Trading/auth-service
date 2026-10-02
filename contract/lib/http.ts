import { request as nodeRequest } from "node:http";

export interface Reply {
  /** "POST /auth/v1/introspect": what was asked, for failure messages. */
  request: string;
  status: number;
  /** Lower-cased names. A header that arrived twice is an array. */
  headers: Record<string, string | string[] | undefined>;
  rawHeaders: string[];
  text: string;
  /** Throws if the body is not JSON, which is itself a failed assertion. */
  json(): unknown;
  header(name: string): string | undefined;
}

export interface RequestOptions {
  method?: string;
  path: string;
  /** Object, or a flat [name, value, name, value] array to send a header twice. */
  headers?: Record<string, string> | string[];
  body?: string | Buffer;
  timeoutMs?: number;
}

/** One request, one connection, no redirects followed, nothing retried. */
export function send(port: number, opts: RequestOptions): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = nodeRequest(
      {
        host: "127.0.0.1",
        port,
        method: opts.method ?? "GET",
        path: opts.path,
        headers: opts.headers as never,
        agent: false,
        timeout: opts.timeoutMs ?? 20_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          resolve({
            request: `${opts.method ?? "GET"} ${opts.path.length > 90 ? `${opts.path.slice(0, 90)}...` : opts.path}`,
            status: res.statusCode ?? 0,
            headers: res.headers,
            rawHeaders: res.rawHeaders,
            text,
            json: () => JSON.parse(text),
            header: (name) => {
              const v = res.headers[name.toLowerCase()];
              return Array.isArray(v) ? v.join(", ") : v;
            },
          });
        });
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error(`request timed out: ${opts.method ?? "GET"} ${opts.path}`)));
    req.on("error", reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export async function waitFor(
  what: string,
  cond: () => boolean | Promise<boolean>,
  timeoutMs = 15_000,
  intervalMs = 100,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await cond()) return;
    if (Date.now() > deadline) throw new Error(`timed out after ${timeoutMs} ms waiting for: ${what}`);
    await sleep(intervalMs);
  }
}
