/**
 * @file The Go corsMiddleware: three constant headers, a 204 for OPTIONS, on every path. Not the `cors` package, which
 * adds Vary and different Allow-Methods. The origin is the one configured value, never reflected from the request.
 * `X-Introspection-Secret` and `X-M2M-Caller-Secret` are deliberately not allowed: no browser calls those routes.
 */

import type { NextFunction, Request, RequestHandler, Response } from "express";

export function corsHeaders(allowedOrigin: string): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Auth-Service-Secret");
    if (req.method === "OPTIONS") {
      res.statusCode = 204;
      res.end();
      return;
    }
    next();
  };
}
