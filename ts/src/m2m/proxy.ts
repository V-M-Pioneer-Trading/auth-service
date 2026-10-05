/**
 * @file Which proxy the Go service's mint request goes through: none, unless the environment names one.
 *
 * The Go minter's `&http.Client{}` uses `http.DefaultTransport`, whose `Proxy` is `ProxyFromEnvironment`
 * (golang.org/x/net/http/httpproxy as vendored in Go 1.22.4): HTTPS_PROXY (or https_proxy) for an https URL,
 * HTTP_PROXY (or http_proxy) for http, except for `localhost`, a loopback address, and whatever NO_PROXY (no_proxy)
 * names; HTTP_PROXY is refused outright under CGI (REQUEST_METHOD set). Neither production nor the contract sets any
 * of these, so the answer there is "direct"; this file reproduces the decision for the case where one is set.
 * `goParity.test.ts` holds it to Go's recorded verdicts. The tunnel itself is Node's (clerk.ts).
 *
 * Not reproduced: a `socks5://` proxy, which Go dials and Node cannot; the mint then fails (fail closed, logged).
 */
import { domainToASCII } from "node:url";

import type { Env } from "../config";
import { goTrimSpace } from "../goText";
import { getScheme, parseHost, unescape } from "../goUrl";

/** A proxy as Go's url.Parse leaves it: what the transport uses of it. */
export interface ProxyUrl {
  readonly scheme: string;
  /** Unescaped, with its port, brackets kept. */
  readonly host: string;
  readonly username?: string;
  readonly password?: string;
}

/** What one request URL gets: no proxy, a proxy, or Go's CGI refusal (the request then fails). */
export type ProxyDecision = { readonly kind: "direct" } | { readonly kind: "proxy"; readonly proxy: ProxyUrl } | { readonly kind: "refused"; readonly reason: string };

// ---- net.ParseIP / net.ParseCIDR (netip.ParseAddr underneath), as Go 1.22 -------------------------------------

/** IPv4 dotted decimal: four fields, no leading zeros, each at most 255. */
function parseIPv4(s: string): number[] | null {
  const fields = s.split(".");
  if (fields.length !== 4) return null;
  const out: number[] = [];
  for (const f of fields) {
    if (!/^[0-9]{1,3}$/.test(f) || (f.length > 1 && f.startsWith("0"))) return null;
    const n = Number(f);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

const hexValue = (c: string): number => (/^[0-9A-Fa-f]$/.test(c) ? parseInt(c, 16) : -1);

/** netip's parseIPv6, zones refused (net.ParseIP and ParseCIDR refuse them). */
function parseIPv6(input: string): Uint8Array | null {
  if (input.includes("%")) return null;
  const ip = new Uint8Array(16);
  let s = input;
  let ellipsis = -1;
  if (s.startsWith("::")) {
    ellipsis = 0;
    s = s.slice(2);
    if (s === "") return ip;
  }
  let i = 0;
  while (i < 16) {
    let off = 0;
    let acc = 0;
    for (; off < s.length; off++) {
      const v = hexValue(s.charAt(off));
      if (v < 0) break;
      acc = acc * 16 + v;
      if (off > 3 || acc > 0xffff) return null;
    }
    if (off === 0) return null;
    if (off < s.length && s.charAt(off) === ".") {
      if ((ellipsis < 0 && i !== 12) || i + 4 > 16) return null;
      const v4 = parseIPv4(s);
      if (v4 === null) return null;
      ip.set(v4, i);
      s = "";
      i += 4;
      break;
    }
    ip[i] = acc >> 8;
    ip[i + 1] = acc & 0xff;
    i += 2;
    s = s.slice(off);
    if (s === "") break;
    if (!s.startsWith(":") || s.length === 1) return null;
    s = s.slice(1);
    if (s.startsWith(":")) {
      if (ellipsis >= 0) return null;
      ellipsis = i;
      s = s.slice(1);
      if (s === "") break;
    }
  }
  if (s !== "") return null;
  if (i < 16) {
    if (ellipsis < 0) return null;
    const n = 16 - i;
    for (let j = i - 1; j >= ellipsis; j--) ip[j + n] = ip[j] ?? 0;
    ip.fill(0, ellipsis, ellipsis + n);
  } else if (ellipsis >= 0) {
    return null;
  }
  return ip;
}

const V4_IN_V6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

/** netip.ParseAddr without a zone: the 16-byte form, and whether it was written as IPv4. */
function parseAddr(s: string): { ip16: Uint8Array; is4: boolean } | null {
  for (const c of s) {
    if (c === ".") {
      const v4 = parseIPv4(s);
      return v4 === null ? null : { ip16: Uint8Array.from([...V4_IN_V6, ...v4]), is4: true };
    }
    if (c === ":") {
      const v6 = parseIPv6(s);
      return v6 === null ? null : { ip16: v6, is4: false };
    }
    if (c === "%") return null;
  }
  return null;
}

/** net.IP.To4: the 4 bytes of a v4-mapped address, else the 16 unchanged. */
function to4(ip16: Uint8Array): Uint8Array {
  return V4_IN_V6.every((b, k) => ip16[k] === b) ? ip16.subarray(12) : ip16;
}

/** net.ParseIP. */
export function goParseIP(s: string): Uint8Array | null {
  return parseAddr(s)?.ip16 ?? null;
}

const isLoopback = (ip16: Uint8Array): boolean => {
  const v = to4(ip16);
  return v.length === 4 ? v[0] === 127 : v.every((b, k) => b === (k === 15 ? 1 : 0));
};

/** net.CIDRMask(ones, bits). */
function cidrMask(ones: number, bits: number): Uint8Array {
  const m = new Uint8Array(bits / 8);
  for (let k = 0; k < m.length; k++) {
    const left = Math.max(0, Math.min(8, ones - k * 8));
    m[k] = (0xff00 >> left) & 0xff;
  }
  return m;
}

interface IpNet {
  readonly network: Uint8Array;
  readonly mask: Uint8Array;
}

/** net.ParseCIDR's network, as IP.Mask leaves it. */
function parseCidr(s: string): IpNet | null {
  const slash = s.indexOf("/");
  if (slash < 0) return null;
  const addr = parseAddr(s.slice(0, slash));
  const maskText = s.slice(slash + 1);
  // dtoi: decimal digits (leading zeros allowed) up to 0xFFFFFF, all of the text.
  if (addr === null || !/^[0-9]+$/.test(maskText)) return null;
  const ones = Number(maskText.length > 8 ? "99999999" : maskText);
  const bits = addr.is4 ? 32 : 128;
  if (ones > bits) return null;
  let mask = cidrMask(ones, bits);
  // IP.Mask.
  let ip: Uint8Array = addr.ip16;
  if (mask.length === 16 && ip.length === 4 && mask.subarray(0, 12).every((b) => b === 0xff)) mask = mask.subarray(12);
  if (mask.length === 4 && ip.length === 16 && V4_IN_V6.every((b, k) => ip[k] === b)) ip = ip.subarray(12);
  const network = ip.map((b, k) => b & (mask[k] ?? 0));
  return { network, mask };
}

/** IPNet.Contains (networkNumberAndMask included). */
function cidrContains(n: IpNet, ip16: Uint8Array): boolean {
  const nn = to4(n.network);
  if (nn.length !== 4 && nn.length !== 16) return false;
  let m = n.mask;
  if (m.length === 4) {
    if (nn.length !== 4) return false;
  } else if (m.length === 16) {
    if (nn.length === 4) m = m.subarray(12);
  } else {
    return false;
  }
  const ip = to4(ip16);
  if (ip.length !== nn.length) return false;
  for (let k = 0; k < ip.length; k++) if (((nn[k] ?? 0) & (m[k] ?? 0)) !== ((ip[k] ?? 0) & (m[k] ?? 0))) return false;
  return true;
}

/** net.SplitHostPort; null for its errors. */
export function goSplitHostPort(hostport: string): [string, string] | null {
  const i = hostport.lastIndexOf(":");
  if (i < 0) return null;
  let host: string;
  let j = 0;
  let k = 0;
  if (hostport.startsWith("[")) {
    const end = hostport.indexOf("]");
    if (end < 0 || end + 1 !== i) return null;
    host = hostport.slice(1, end);
    j = 1;
    k = end + 1;
  } else {
    host = hostport.slice(0, i);
    if (host.includes(":")) return null;
  }
  if (hostport.slice(j).includes("[") || hostport.slice(k).includes("]")) return null;
  return [host, hostport.slice(i + 1)];
}

/** net.JoinHostPort. */
const joinHostPort = (host: string, port: string): string => (host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`);

/** httpproxy's idnaASCII: ASCII unchanged; otherwise IDNA lookup, and the input kept when that fails. */
function idnaAscii(v: string): string {
  if (/^[\x00-\x7f]*$/.test(v)) return v;
  const ascii = domainToASCII(v);
  return ascii === "" ? v : ascii;
}

// ---- url.Parse, for what the transport reads of a proxy URL ----------------------------------------------------

/** Go's validUserinfo. */
const validUserinfo = (s: string): boolean => /^[A-Za-z0-9\-._:~!$&'()*+,;=%@]*$/.test(s);

/** url.Parse(raw): the scheme (lower case), host and userinfo, or null for an error. */
export function goParseUrl(raw: string): ProxyUrl | null {
  const hash = raw.indexOf("#");
  const beforeFragment = hash < 0 ? raw : raw.slice(0, hash);
  if (hash >= 0 && unescape(Buffer.from(raw.slice(hash + 1), "utf8"), "path") === null) return null;
  for (const byte of Buffer.from(beforeFragment, "utf8")) if (byte < 0x20 || byte === 0x7f) return null;
  if (beforeFragment === "*") return { scheme: "", host: "" };
  const split = getScheme(beforeFragment);
  if (split === null) return null;
  const scheme = split[0].toLowerCase();
  let rest = split[1];
  if (rest.endsWith("?") && rest.split("?").length === 2) rest = rest.slice(0, -1);
  else if (rest.includes("?")) rest = rest.slice(0, rest.indexOf("?"));
  if (!rest.startsWith("/")) {
    if (scheme !== "") return { scheme, host: "" }; // opaque
    const segment = rest.includes("/") ? rest.slice(0, rest.indexOf("/")) : rest;
    if (segment.includes(":")) return null;
  }
  let host = "";
  let username: string | undefined;
  let password: string | undefined;
  if (rest.startsWith("//") && (scheme !== "" || !rest.startsWith("///"))) {
    let authority = rest.slice(2);
    const slash = authority.indexOf("/");
    rest = slash < 0 ? "" : authority.slice(slash);
    authority = slash < 0 ? authority : authority.slice(0, slash);
    const at = authority.lastIndexOf("@");
    const parsedHost = parseHost(Buffer.from(at < 0 ? authority : authority.slice(at + 1), "utf8"));
    if (parsedHost === null) return null;
    host = parsedHost.toString("utf8");
    if (at >= 0) {
      const userinfo = authority.slice(0, at);
      if (!validUserinfo(userinfo)) return null;
      const colon = userinfo.indexOf(":");
      const user = unescape(Buffer.from(colon < 0 ? userinfo : userinfo.slice(0, colon), "utf8"), "path");
      const pass = colon < 0 ? Buffer.alloc(0) : unescape(Buffer.from(userinfo.slice(colon + 1), "utf8"), "path");
      if (user === null || pass === null) return null;
      username = user.toString("utf8");
      if (colon >= 0) password = pass.toString("utf8");
    }
  }
  if (unescape(Buffer.from(rest, "utf8"), "path") === null) return null;
  return { scheme, host, ...(username === undefined ? {} : { username }), ...(password === undefined ? {} : { password }) };
}

/** httpproxy's parseProxy: the value, or "http://" + the value when the first is not an http, https or socks5 URL. */
function parseProxy(value: string): ProxyUrl | undefined {
  if (value === "") return undefined;
  const first = goParseUrl(value);
  if (first === null || !["http", "https", "socks5"].includes(first.scheme)) {
    const prefixed = goParseUrl(`http://${value}`);
    if (prefixed !== null) return prefixed;
  }
  return first ?? undefined;
}

// ---- the decision ----------------------------------------------------------------------------------------------

type Matcher = (host: string, port: string, ip: Uint8Array | null) => boolean;

export interface ProxyConfig {
  readonly httpProxy: ProxyUrl | undefined;
  readonly httpsProxy: ProxyUrl | undefined;
  readonly cgi: boolean;
  readonly ipMatchers: readonly Matcher[];
  readonly domainMatchers: readonly Matcher[];
}

const firstSet = (env: Env, ...names: string[]): string => {
  for (const n of names) {
    const v = env[n];
    if (v !== undefined && v !== "") return v;
  }
  return "";
};

/** httpproxy.FromEnvironment().ProxyFunc()'s preprocessing (config.init). */
export function proxyConfigFrom(env: Env): ProxyConfig {
  const ipMatchers: Matcher[] = [];
  const domainMatchers: Matcher[] = [];
  const base = {
    httpProxy: parseProxy(firstSet(env, "HTTP_PROXY", "http_proxy")),
    httpsProxy: parseProxy(firstSet(env, "HTTPS_PROXY", "https_proxy")),
    cgi: (env.REQUEST_METHOD ?? "") !== "",
  };
  for (const entry of firstSet(env, "NO_PROXY", "no_proxy").split(",")) {
    const p = goTrimSpace(entry).toLowerCase();
    if (p === "") continue;
    if (p === "*") return { ...base, ipMatchers: [() => true], domainMatchers: [() => true] };
    const cidr = parseCidr(p);
    if (cidr !== null) {
      ipMatchers.push((_h, _p, ip) => ip !== null && cidrContains(cidr, ip));
      continue;
    }
    let phost: string;
    let pport = "";
    const split = goSplitHostPort(p);
    if (split !== null) {
      [phost, pport] = split;
      if (phost === "") continue;
      if (phost.startsWith("[") && phost.endsWith("]")) phost = phost.slice(1, -1);
    } else {
      phost = p;
    }
    const pip = goParseIP(phost);
    if (pip !== null) {
      ipMatchers.push((_h, port, ip) => ip !== null && ip.every((b, k) => b === pip[k]) && (pport === "" || pport === port));
      continue;
    }
    if (phost === "") continue;
    if (phost.startsWith("*.")) phost = phost.slice(1);
    let matchHost = false;
    if (!phost.startsWith(".")) {
      matchHost = true;
      phost = `.${phost}`;
    }
    const suffix = idnaAscii(phost);
    domainMatchers.push((host, port) => (host.endsWith(suffix) || (matchHost && host === suffix.slice(1))) && (pport === "" || pport === port));
  }
  return { ...base, ipMatchers, domainMatchers };
}

/** useProxy(addr): addr is canonicalAddr's host:port. */
function useProxy(cfg: ProxyConfig, addr: string): boolean {
  if (addr === "") return true;
  const split = goSplitHostPort(addr);
  if (split === null) return false;
  const [host, port] = split;
  if (host === "localhost") return false;
  const ip = goParseIP(host);
  if (ip !== null && isLoopback(ip)) return false;
  const lower = goTrimSpace(host).toLowerCase();
  if (ip !== null && cfg.ipMatchers.some((m) => m(lower, port, ip))) return false;
  return !cfg.domainMatchers.some((m) => m(lower, port, ip));
}

const DEFAULT_PORTS: Record<string, string> = { http: "80", https: "443", socks5: "1080" };

/**
 * proxyForURL for a request to `scheme://host` (host as Go's url.Parse leaves it: unescaped, with its port).
 */
export function proxyFor(cfg: ProxyConfig, scheme: string, host: string): ProxyDecision {
  let proxy: ProxyUrl | undefined;
  if (scheme === "https") proxy = cfg.httpsProxy;
  else if (scheme === "http") {
    proxy = cfg.httpProxy;
    if (proxy !== undefined && cfg.cgi) return { kind: "refused", reason: "refusing to use HTTP_PROXY value in CGI environment; see golang.org/s/cgihttpproxy" };
  }
  if (proxy === undefined) return { kind: "direct" };
  // canonicalAddr: url.Hostname(), IDNA, url.Port() or the scheme's default.
  let name = host;
  let port = "";
  const colon = name.lastIndexOf(":");
  if (colon !== -1 && /^:[0-9]*$/.test(name.slice(colon))) {
    port = name.slice(colon + 1);
    name = name.slice(0, colon);
  }
  if (name.startsWith("[") && name.endsWith("]")) name = name.slice(1, -1);
  const addr = joinHostPort(idnaAscii(name), port === "" ? (DEFAULT_PORTS[scheme] ?? "") : port);
  return useProxy(cfg, addr) ? { kind: "proxy", proxy } : { kind: "direct" };
}
