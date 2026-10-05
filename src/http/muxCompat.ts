/**
 * @file The gorilla/mux and net/http artefacts the contract suite pins (contract/README.md "Routing", notes 1-7),
 * reproduced in front of Express.
 *
 *  - a malformed percent escape in the path: bare `400 Bad Request`, connection closed;
 *  - an unclean (decoded) path: `301` to the cleaned path, query kept, for every method;
 *  - routing is on the decoded path: the URL Express sees is the decoded path with every byte that is not a plain
 *    path character escaped again, so `%2F` becomes a real slash (and splits the segment, as mux does) and `%2561`
 *    is `%61`, decoded once;
 *  - HEAD is never served: it is not routed at all (Express would answer a GET route's HEAD);
 *  - the terminal answers (`terminalAnswer`): under the string prefix `/api/auth` a path no route takes is
 *    `404 page not found`, with one exception, and everywhere else it is a bare `405`.
 *
 * All of it comes before any Express default or route.
 */

import type { IncomingMessage } from "node:http";
import type { NextFunction, Request, RequestHandler, Response } from "express";

const API_PREFIX = "/api/auth";
/** The one path under the prefix whose wrong methods are 405, not 404 (README note 1). */
const REGISTER_PATH = "/api/auth/v1/register";
const TEXT = "text/plain; charset=utf-8";

/** Percent-decode to bytes; null for a `%` not followed by two hex digits (Go's url.unescape). */
export function unescapeBytes(raw: string): Buffer | null {
  const out: number[] = [];
  const bytes = Buffer.from(raw, "latin1");
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i] ?? 0;
    if (c !== 0x25) {
      out.push(c);
      continue;
    }
    const hex = bytes.toString("latin1", i + 1, i + 3);
    if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return null;
    out.push(parseInt(hex, 16));
    i += 2;
  }
  return Buffer.from(out);
}

/** gorilla/mux cleanPath: path.Clean on a rooted path, trailing slash kept. */
export function cleanPath(p: string): string {
  if (p === "") return "/";
  const rooted = p.startsWith("/") ? p : `/${p}`;
  const out: string[] = [];
  for (const seg of rooted.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") out.pop();
    else out.push(seg);
  }
  const clean = `/${out.join("/")}`;
  return rooted.endsWith("/") && clean !== "/" ? `${clean}/` : clean;
}

const isUnreserved = (c: number): boolean =>
  (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x2d || c === 0x5f || c === 0x2e || c === 0x7e;

function escapeWith(bytes: Buffer, keep: string): string {
  let out = "";
  for (const c of bytes) {
    out += isUnreserved(c) || keep.includes(String.fromCharCode(c)) ? String.fromCharCode(c) : `%${c.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

/** Go's URL.String() path form, for the Location of a redirect. */
const escapeForLocation = (bytes: Buffer): string => escapeWith(bytes, "$&+,/:;=@");
/** What Express routes on: the decoded path, escaped again except "/" and the sub-delimiters that cannot change the parse. */
const escapeForRouting = (bytes: Buffer): string => escapeWith(bytes, "/!$&'()*+,;=:@");

const decodedPaths = new WeakMap<IncomingMessage, Buffer>();
/** The request path after percent-decoding, as mux sees it: raw bytes. */
export const decodedPathOf = (req: IncomingMessage): Buffer => decodedPaths.get(req) ?? Buffer.alloc(0);

const CORS_HEADER_NAMES = ["Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"];

function badRequest(res: Response): void {
  res.statusCode = 400;
  res.setHeader("Content-Type", TEXT);
  res.setHeader("Connection", "close");
  res.end("400 Bad Request");
}

export const muxCompat: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
  // Absolute-form ("GET http://host/path HTTP/1.1"): Go routes on the URL's path, so do we.
  // An empty path ("GET http://host") is "" there, which mux cleans to "/": a 301.
  const absolute = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?]*)([\s\S]*)$/.exec(req.url);
  const target = absolute === null ? req.url : (absolute[2] ?? "");
  // A "#" in the authority is an invalid host for Go's parser: 400 ("GET http://h#f").
  if ((absolute !== null && (absolute[1] ?? "").includes("#")) || (absolute === null && !target.startsWith("/"))) {
    // "OPTIONS *" is answered by Go's server itself (200, empty); here it is a 400. No caller sends it.
    badRequest(res);
    return;
  }
  const q = target.indexOf("?");
  const rawPath = q === -1 ? target : target.slice(0, q);
  const query = q === -1 ? "" : target.slice(q); // "?" included, also an empty query

  const decoded = unescapeBytes(rawPath);
  if (decoded === null) {
    badRequest(res);
    return;
  }
  const decodedStr = decoded.toString("latin1");
  const cleaned = cleanPath(decodedStr);
  if (cleaned !== decodedStr) {
    res.statusCode = 301;
    res.setHeader("Location", escapeForLocation(Buffer.from(cleaned, "latin1")) + query);
    res.end();
    return;
  }
  decodedPaths.set(req, decoded);
  req.url = escapeForRouting(Buffer.from(decoded.toString("utf8"), "utf8")) + query;
  next();
};

/** net/http's NotFound, which is what a path under /api/auth that no route takes gets. */
export function pageNotFound(res: Response): void {
  // CORS headers belong to a matched route; this answer is for none.
  for (const name of CORS_HEADER_NAMES) res.removeHeader(name);
  res.status(404);
  res.setHeader("Content-Type", TEXT);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end("404 page not found\n");
}

/** The terminal handler: the answer for a request no route took. */
export const terminalAnswer = (req: Request, res: Response): void => {
  if (req.path.startsWith(API_PREFIX) && !(req.path === REGISTER_PATH && req.method !== "POST")) {
    pageNotFound(res);
    return;
  }
  for (const name of CORS_HEADER_NAMES) res.removeHeader(name);
  // A catch-all OPTIONS route in the Go router makes every other method "a wrong method on a path that exists":
  // a bare 405, no body, no Allow. Under /api/auth that holds for the register path alone.
  res.status(405).end();
};

/**
 * HEAD is never routed, not even on a GET route: Go's mux has no automatic HEAD, and Express would serve it from the
 * GET handler. Straight to the terminal answer.
 */
export const noHead: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
  if (req.method === "HEAD") {
    terminalAnswer(req, res);
    return;
  }
  next();
};
