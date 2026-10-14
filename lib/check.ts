/**
 * Free Website Health Check: server-side logic.
 *
 * Ported from the internal Python script `kiem-tra-web.py`. Checks a public website for:
 * uptime / hosting default page / response time, SSL certificate, call (tel:), email (mailto:)
 * and Zalo links, email domain MX records, placeholder title, injected spam links, heavy images
 * and page HTML size.
 *
 * SECURITY: this module fetches URLs supplied by anonymous visitors, so every outbound request
 * goes through an SSRF guard:
 *  - only http/https on the default ports (80/443);
 *  - the hostname must be a public DNS name (no IP literals, localhost, *.local, *.internal,
 *    single-label names...);
 *  - every address the name resolves to must be public (checked before the request AND again
 *    inside the socket `lookup` hook, so a DNS answer that changes between check and connect
 *    is still caught);
 *  - redirects are followed manually (max 3) and each hop is re-validated;
 *  - per-request and total timeouts, a body size cap, GET/HEAD only, no cookies or credentials.
 *
 * This file only imports Node built-ins (no relative imports) so it can be unit-tested directly
 * with `node --experimental-strip-types`.
 */
import dns from 'node:dns';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import zlib from 'node:zlib';

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------
export const PER_REQUEST_TIMEOUT_MS = 10_000;
export const TOTAL_TIMEOUT_MS = 25_000;
export const MAX_BODY_BYTES = 2 * 1024 * 1024;
export const MAX_REDIRECTS = 3;
export const MAX_IMAGES = 20;
export const HEAVY_IMAGE_KB = 500;
const MAX_EMAIL_DOMAINS = 5;

const UA =
  'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Mobile Safari/537.36 HoangThongWebsiteCheck/1.0';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
export class CheckInputError extends Error {
  status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

function errCode(e: unknown): string {
  if (e && typeof e === 'object' && 'code' in e) return String((e as { code: unknown }).code);
  return '';
}

function blockedError(): NodeJS.ErrnoException {
  const e = new Error('Address is not public') as NodeJS.ErrnoException;
  e.code = 'EBLOCKED';
  return e;
}

// ---------------------------------------------------------------------------
// IP address classification
// ---------------------------------------------------------------------------
const V4_BLOCKED: [string, number][] = [
  ['0.0.0.0', 8], // "this" network
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local (cloud metadata lives here)
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.88.99.0', 24], // 6to4 relay anycast
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved + broadcast
];

function ipv4ToInt(ip: string): number {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function isBlockedIPv4Int(n: number): boolean {
  return V4_BLOCKED.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return ((n & mask) >>> 0) === ((ipv4ToInt(base) & mask) >>> 0);
  });
}

/** Parse an IPv6 address into 8 16-bit groups, or null if invalid. */
export function parseIPv6(ip: string): number[] | null {
  let s = ip.toLowerCase().replace(/^\[|\]$/g, '');
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);
  let embedded: [number, number] | null = null;
  const lastColon = s.lastIndexOf(':');
  if (lastColon < 0) return null;
  const tail = s.slice(lastColon + 1);
  if (tail.includes('.')) {
    if (!net.isIPv4(tail)) return null;
    const n = ipv4ToInt(tail);
    embedded = [n >>> 16, n & 0xffff];
    s = s.slice(0, lastColon + 1) + '0:0';
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  if (fill < 0) return null;
  const groups = [...head, ...Array(fill).fill('0'), ...rest];
  if (groups.length !== 8) return null;
  const out: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  if (embedded) {
    out[6] = embedded[0];
    out[7] = embedded[1];
  }
  return out;
}

function isBlockedIPv6(ip: string): boolean {
  const h = parseIPv6(ip);
  if (!h) return true;
  const v4At = (hi: number, lo: number) => isBlockedIPv4Int(((hi << 16) >>> 0) + lo);
  // ::ffff:a.b.c.d (IPv4-mapped) -> judge the embedded IPv4 address
  if (h.slice(0, 5).every((x) => x === 0) && h[5] === 0xffff) return v4At(h[6], h[7]);
  // NAT64 well-known prefix 64:ff9b::/96 -> judge embedded IPv4
  if (h[0] === 0x64 && h[1] === 0xff9b && h.slice(2, 6).every((x) => x === 0)) return v4At(h[6], h[7]);
  // 6to4 2002::/16 -> judge embedded IPv4
  if (h[0] === 0x2002) return v4At(h[1], h[2]);
  // Everything outside global unicast 2000::/3 is blocked: ::, ::1, ::/96, fc00::/7 (ULA),
  // fe80::/10 (link-local), ff00::/8 (multicast), 100::/64 (discard), 64:ff9b:1::/48 ...
  if ((h[0] & 0xe000) !== 0x2000) return true;
  // Special-purpose ranges inside 2000::/3
  if (h[0] === 0x2001 && h[1] < 0x0200) return true; // 2001::/23 (Teredo, ORCHID, benchmarking...)
  if (h[0] === 0x2001 && h[1] === 0x0db8) return true; // 2001:db8::/32 documentation
  if ((h[0] & 0xfff0) === 0x3ff0) return true; // 3fff::/20 documentation
  return false;
}

/** True when an IP address is NOT a normal public unicast address. */
export function isBlockedIp(ip: string): boolean {
  if (net.isIPv4(ip)) return isBlockedIPv4Int(ipv4ToInt(ip));
  if (net.isIPv6(ip)) return isBlockedIPv6(ip);
  return true;
}

// ---------------------------------------------------------------------------
// Hostname / URL validation
// ---------------------------------------------------------------------------
const BLOCKED_SUFFIXES = [
  'localhost',
  'localdomain',
  'local',
  'internal',
  'intranet',
  'lan',
  'home',
  'corp',
  'private',
  'test',
  'example',
  'invalid',
  'onion',
  'arpa',
];

/** Returns an error message if the hostname is not an acceptable public DNS name, else null. */
export function hostnameProblem(hostnameRaw: string): string | null {
  const hostname = hostnameRaw.toLowerCase().replace(/\.$/, '');
  if (!hostname) return 'Please enter a website address.';
  if (hostname.startsWith('[') || net.isIP(hostname)) {
    return 'Please enter a domain name (like example.com), not an IP address.';
  }
  if (hostname.length > 253) return 'That domain name is too long.';
  const labels = hostname.split('.');
  if (labels.length < 2) return 'Please enter a full domain name, like example.com.';
  for (const l of labels) {
    if (!/^[a-z0-9-]{1,63}$/.test(l) || l.startsWith('-') || l.endsWith('-')) {
      return 'That doesn’t look like a valid domain name.';
    }
  }
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,63}$/.test(tld) && !/^xn--[a-z0-9-]{1,59}$/.test(tld)) {
    return 'That doesn’t look like a valid domain name.';
  }
  if (BLOCKED_SUFFIXES.some((s) => hostname === s || hostname.endsWith('.' + s))) {
    return 'Only public websites can be checked.';
  }
  return null;
}

function portProblem(u: URL): boolean {
  return u.port !== '' && u.port !== '80' && u.port !== '443';
}

/** Turn user input into `https://host/`. Throws CheckInputError on bad input. */
export function normalizeInput(raw: unknown): { host: string; url: string } {
  if (typeof raw !== 'string') throw new CheckInputError('Please enter a website address.');
  let s = raw.trim();
  if (!s) throw new CheckInputError('Please enter a website address.');
  if (s.length > 500) throw new CheckInputError('That address is too long.');
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(s);
  if (scheme && !/^https?$/i.test(scheme[1]) && !/^[^/]*\.[^/]*:\d/.test(s)) {
    // e.g. ftp:, file:, javascript:, gopher: ... ("example.com:443" is not a scheme)
    throw new CheckInputError('Only http and https websites can be checked.');
  }
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s.replace(/^\/+/, '');
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new CheckInputError('That doesn’t look like a valid website address.');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new CheckInputError('Only http and https websites can be checked.');
  }
  if (portProblem(u)) throw new CheckInputError('Only websites on the standard ports (80/443) can be checked.');
  const problem = hostnameProblem(u.hostname);
  if (problem) throw new CheckInputError(problem);
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  return { host, url: `https://${host}/` };
}

// ---------------------------------------------------------------------------
// DNS with public-address enforcement
// ---------------------------------------------------------------------------
type LookupAddr = { address: string; family: number };

function lookupAll(hostname: string): Promise<LookupAddr[]> {
  return new Promise((resolve, reject) => {
    dns.lookup(hostname, { all: true, verbatim: true }, (err, addrs) => {
      if (err) reject(err);
      else resolve(addrs as LookupAddr[]);
    });
  });
}

/**
 * Socket-level lookup hook used for every outbound connection. Rejects the connection if ANY
 * resolved address is non-public (defends against DNS rebinding between check and connect).
 */
export function safeLookup(hostname: string, options: any, callback?: any): void {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  } else if (typeof options === 'number') {
    options = { family: options };
  }
  options = options || {};
  if (net.isIP(hostname)) {
    // Only reached for redirects we already refuse; keep it strict anyway.
    const fam = net.isIP(hostname);
    if (isBlockedIp(hostname)) return callback(blockedError());
    return options.all ? callback(null, [{ address: hostname, family: fam }]) : callback(null, hostname, fam);
  }
  if (hostnameProblem(hostname)) return callback(blockedError());
  lookupAll(hostname).then(
    (addrs) => {
      if (!addrs.length) {
        const e = new Error('No addresses') as NodeJS.ErrnoException;
        e.code = 'ENOTFOUND';
        return callback(e);
      }
      if (addrs.some((a) => isBlockedIp(a.address))) return callback(blockedError());
      let list = addrs;
      if (options.family === 4 || options.family === 6) {
        list = addrs.filter((a) => a.family === options.family);
        if (!list.length) {
          const e = new Error('No address for requested family') as NodeJS.ErrnoException;
          e.code = 'ENOTFOUND';
          return callback(e);
        }
      }
      if (options.all) return callback(null, list);
      return callback(null, list[0].address, list[0].family);
    },
    (err) => callback(err),
  );
}

/** Resolve a hostname and throw if it is invalid, unknown or resolves to a non-public address. */
export async function assertPublicHost(hostname: string): Promise<void> {
  const problem = hostnameProblem(hostname);
  if (problem) throw new CheckInputError(problem);
  let addrs: LookupAddr[];
  try {
    addrs = await lookupAll(hostname);
  } catch {
    throw new CheckInputError(
      'We couldn’t find that domain. Please check the spelling (for example: yourbusiness.com).',
      422,
    );
  }
  if (!addrs.length) throw new CheckInputError('We couldn’t find that domain.', 422);
  if (addrs.some((a) => isBlockedIp(a.address))) {
    throw new CheckInputError('Only public websites can be checked.');
  }
}

// ---------------------------------------------------------------------------
// Safe HTTP client
// ---------------------------------------------------------------------------
type HopResult = {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  truncated: boolean;
};

export type SafeResponse = HopResult & { finalUrl: string; ms: number; redirects: number };

type SafeRequestOptions = {
  method?: 'GET' | 'HEAD';
  insecure?: boolean; // accept invalid TLS certs (to read a page whose SSL is broken)
  deadline: number; // epoch ms; whole operation must end before this
  maxBytes?: number;
};

function timeLeft(deadline: number): number {
  return Math.min(PER_REQUEST_TIMEOUT_MS, deadline - Date.now());
}

function requestOnce(u: URL, method: 'GET' | 'HEAD', insecure: boolean, timeoutMs: number, maxBytes: number): Promise<HopResult> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const isHttps = u.protocol === 'https:';
    const mod = isHttps ? https : http;
    const opts: https.RequestOptions = {
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: (u.pathname || '/') + u.search,
      method,
      agent: false, // fresh socket every time: no pooled connections reused across hosts
      lookup: safeLookup as any,
      headers: {
        'User-Agent': UA,
        Accept: method === 'HEAD' ? '*/*' : 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5',
        'Accept-Language': 'en,vi;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        Connection: 'close',
      },
    };
    if (isHttps) {
      opts.servername = u.hostname;
      opts.rejectUnauthorized = !insecure;
    }
    const req = mod.request(opts, (res) => {
      const status = res.statusCode || 0;
      const headers = res.headers;
      if (method === 'HEAD' || (status >= 300 && status < 400)) {
        res.resume();
        finish(() => resolve({ status, headers, body: Buffer.alloc(0), truncated: false }));
        req.destroy();
        return;
      }
      const enc = String(headers['content-encoding'] || '').toLowerCase().trim();
      let stream: NodeJS.ReadableStream = res;
      if (enc === 'gzip' || enc === 'x-gzip') stream = res.pipe(zlib.createGunzip());
      else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
      else if (enc === 'br') stream = res.pipe(zlib.createBrotliDecompress());
      const chunks: Buffer[] = [];
      let size = 0;
      let truncated = false;
      const done = () =>
        finish(() => resolve({ status, headers, body: Buffer.concat(chunks), truncated }));
      stream.on('data', (c: Buffer) => {
        if (truncated) return;
        const room = maxBytes - size;
        if (c.length > room) {
          if (room > 0) chunks.push(c.subarray(0, room));
          size = maxBytes;
          truncated = true;
          done();
          req.destroy();
          return;
        }
        chunks.push(c);
        size += c.length;
      });
      stream.on('end', done);
      // A decompression error or socket reset mid-body: keep what we have.
      stream.on('error', done);
      res.on('error', done);
    });
    const timer = setTimeout(() => {
      const e = new Error('Request timed out') as NodeJS.ErrnoException;
      e.code = 'ETIMEDOUT';
      req.destroy(e);
      finish(() => reject(e));
    }, Math.max(timeoutMs, 1));
    req.on('error', (e) => finish(() => reject(e)));
    req.end();
  });
}

/** GET/HEAD a public URL with manual, re-validated redirects. */
export async function safeRequest(url: string, o: SafeRequestOptions): Promise<SafeResponse> {
  const method = o.method || 'GET';
  const maxBytes = o.maxBytes ?? MAX_BODY_BYTES;
  const t0 = Date.now();
  let current = new URL(url);
  for (let hop = 0; ; hop++) {
    if (current.protocol !== 'http:' && current.protocol !== 'https:') throw blockedError();
    if (portProblem(current) || current.username || current.password) throw blockedError();
    if (hostnameProblem(current.hostname)) throw blockedError();
    // Pre-flight DNS check (the socket lookup hook checks again at connect time).
    const addrs = await lookupAll(current.hostname);
    if (!addrs.length || addrs.some((a) => isBlockedIp(a.address))) throw blockedError();
    const left = timeLeft(o.deadline);
    if (left < 300) {
      const e = new Error('Out of time') as NodeJS.ErrnoException;
      e.code = 'ETIMEDOUT';
      throw e;
    }
    const r = await requestOnce(current, method, !!o.insecure, left, maxBytes);
    const loc = r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc && hop < MAX_REDIRECTS) {
      try {
        current = new URL(String(loc), current);
      } catch {
        return { ...r, finalUrl: current.toString(), ms: Date.now() - t0, redirects: hop };
      }
      continue;
    }
    if (r.status >= 300 && r.status < 400 && loc) {
      const e = new Error('Too many redirects') as NodeJS.ErrnoException;
      e.code = 'ETOOMANYREDIRECTS';
      throw e;
    }
    return { ...r, finalUrl: current.toString(), ms: Date.now() - t0, redirects: hop };
  }
}

// ---------------------------------------------------------------------------
// SSL certificate
// ---------------------------------------------------------------------------
export type SslResult = {
  ok: boolean;
  daysLeft: number | null;
  expires: string | null; // ISO date
  error: string | null; // plain-language
  code?: string;
  chainIncomplete?: boolean;
  noHttps?: boolean;
};

const SSL_MESSAGES: Record<string, string> = {
  CERT_HAS_EXPIRED: 'The SSL certificate has expired.',
  CERT_NOT_YET_VALID: 'The SSL certificate is not valid yet (check the server clock or the certificate dates).',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'The SSL certificate is self-signed, so browsers don’t trust it.',
  SELF_SIGNED_CERT_IN_CHAIN: 'The SSL certificate chain contains a self-signed certificate, so browsers don’t trust it.',
  ERR_TLS_CERT_ALTNAME_INVALID: 'The SSL certificate was issued for a different domain name.',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'The server is missing an intermediate certificate.',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'The server is missing an intermediate certificate.',
  UNABLE_TO_GET_ISSUER_CERT: 'The server is missing an intermediate certificate.',
  CERT_REVOKED: 'The SSL certificate has been revoked.',
};

const CHAIN_CODES = new Set([
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_GET_ISSUER_CERT',
]);

export function checkSsl(host: string, deadline: number): Promise<SslResult> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (r: SslResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(r);
    };
    const socket = tls.connect({
      host,
      port: 443,
      servername: host,
      rejectUnauthorized: false, // we read authorized/authorizationError ourselves
      lookup: safeLookup as any,
      ALPNProtocols: ['http/1.1'],
    });
    const timer = setTimeout(
      () => done({ ok: false, daysLeft: null, expires: null, error: 'The secure (HTTPS) connection timed out.', code: 'ETIMEDOUT' }),
      Math.max(timeLeft(deadline), 1),
    );
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      let expires: string | null = null;
      let daysLeft: number | null = null;
      if (cert && cert.valid_to) {
        const t = new Date(cert.valid_to);
        if (!Number.isNaN(t.getTime())) {
          expires = t.toISOString();
          daysLeft = Math.floor((t.getTime() - Date.now()) / 86_400_000);
        }
      }
      let code = socket.authorized ? '' : String(socket.authorizationError || '');
      if (!code && cert && cert.subject) {
        // Belt and braces: explicit hostname check.
        const idErr = tls.checkServerIdentity(host, cert);
        if (idErr) code = 'ERR_TLS_CERT_ALTNAME_INVALID';
      }
      if (!code) return done({ ok: true, daysLeft, expires, error: null });
      done({
        ok: false,
        daysLeft,
        expires,
        code,
        chainIncomplete: CHAIN_CODES.has(code),
        error: SSL_MESSAGES[code] || `The SSL certificate is not trusted (${code}).`,
      });
    });
    socket.once('error', (e) => {
      const code = errCode(e);
      if (code === 'EBLOCKED') return done({ ok: false, daysLeft: null, expires: null, error: 'Blocked.', code });
      const noHttps = ['ECONNREFUSED', 'ECONNRESET', 'EPROTO', 'EHOSTUNREACH', 'ENETUNREACH'].includes(code) ||
        /wrong version number|handshake failure|alert/i.test(String((e as Error).message));
      done({
        ok: false,
        daysLeft: null,
        expires: null,
        code,
        noHttps,
        error: noHttps
          ? 'The website doesn’t accept secure (HTTPS) connections.'
          : 'Couldn’t open a secure (HTTPS) connection to the website.',
      });
    });
  });
}

// ---------------------------------------------------------------------------
// HTML analysis (ported from kiem-tra-web.py)
// ---------------------------------------------------------------------------
export type Severity = 'critical' | 'warning';
export type Finding = { type: string; severity: Severity; message: string };

const SPAM_WORDS =
  /(^|[^a-z])(casino|cá cược|ca-cuoc|slot|bet88|nhà cái|nha-cai|w88|fb88|viagra|cialis|porn|sex|payday|loan|tax-software|turbotax|ez4tax)([^a-z]|$)/i;
const PLACEHOLDER_EMAILS =
  /^(your@email|abcd@gmail\.com|email@example\.com|info@example\.com|youremail@|example@|test@|admin@admin|name@domain|email@domain|info@domain|someone@)/i;
const EMAIL_TYPO_DOMAINS = new Set(['gmai.com', 'gmial.com', 'gamil.com', 'gmail.co', 'gmail.con', 'gmal.com', 'yahoo.co', 'yahoo.con', 'hotmai.com']);
const WELL_KNOWN_MAIL = new Set(['gmail.com', 'yahoo.com', 'yahoo.com.vn', 'outlook.com', 'hotmail.com', 'icloud.com', 'live.com']);

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'",
};

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+\d*);/gi, (m, e: string) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      try {
        return Number.isFinite(n) ? String.fromCodePoint(n) : m;
      } catch {
        return m;
      }
    }
    return NAMED_ENTITIES[e.toLowerCase()] ?? m;
  });
}

function safeDecodeURI(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function stripTags(s: string): string {
  return s.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

function short(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

/** Returns a plain-language reason why a tel: value is wrong, or null if it looks fine. */
export function checkTel(hrefAfterScheme: string): string | null {
  const v = safeDecodeURI(hrefAfterScheme).trim();
  if (!v || v.startsWith('#')) return 'the call link is empty (or just “#”)';
  if (/^(tel:|tel\/\/|\/\/)/i.test(v)) return '“tel:” is written twice or the format is broken';
  if (/[a-zA-ZÀ-ỹ<>]/.test(v)) return 'it contains letters or HTML (for example the letter “O” instead of zero), so phones can’t dial it';
  if (/\d[\s.]*[-/,;][\s.]*0\d/.test(v) || v.replace(/\D/g, '').length > 13) {
    return 'several phone numbers are packed into one link, so phones dial a wrong number';
  }
  const d = v.replace(/[^\d+]/g, '');
  if (d.startsWith('+') && !d.startsWith('+84') && !d.startsWith('++') && !d.startsWith('+0')) {
    return null; // non-Vietnamese international number: not judged
  }
  if (d.startsWith('++')) return 'it has an extra “+”';
  if (d.startsWith('+840')) return 'it has “+84” followed by a 0 (should be +84 then the number without its leading 0)';
  if (d.startsWith('+0')) return 'a “+” comes before the 0';
  const digits = d.replace(/\D/g, '');
  if (d.startsWith('+84')) {
    const n = digits.length - 2;
    if (n !== 9 && n !== 10) return `the number has ${n} digits after +84 (expected 9 or 10)`;
  } else if (digits.startsWith('1900') || digits.startsWith('1800')) {
    if (digits.length !== 8 && digits.length !== 10) return `the 1900/1800 hotline has ${digits.length} digits (expected 8 or 10)`;
  } else if (digits.startsWith('0')) {
    if (digits.length !== 10 && digits.length !== 11) return `the number has ${digits.length} digits (a Vietnamese number needs 10, landlines 11)`;
  } else {
    return 'the leading 0 is missing';
  }
  return null;
}

/** Returns [problem, domain]. */
export function checkMailto(hrefAfterScheme: string): [string | null, string | null] {
  const v = safeDecodeURI(hrefAfterScheme.split('?')[0]).trim();
  if (!v) return ['the email link is empty', null];
  if (/^(mailto:|maito:|#)/i.test(v)) return ['“mailto:” is repeated/misspelled or there is a stray “#”', null];
  if (PLACEHOLDER_EMAILS.test(v)) return ['it is still the theme’s sample email address', null];
  if (!/^[\w.+-]+@[\w-]+(\.[\w-]+)+$/.test(v)) return ['the email address is not valid', null];
  const dom = v.split('@')[1].toLowerCase();
  if (EMAIL_TYPO_DOMAINS.has(dom)) return [`the email domain looks like a typo (${dom})`, null];
  return [null, dom];
}

export type HtmlAnalysis = {
  findings: Finding[];
  title: string;
  images: string[];
  telCount: number;
  mailCount: number;
  emailDomains: string[];
  telOk: boolean;
  mailOk: boolean;
  zaloOk: boolean;
  spamFree: boolean;
};

export function analyzeHtml(text: string, base: string): HtmlAnalysis {
  const findings: Finding[] = [];
  const hrefs = Array.from(text.matchAll(/href\s*=\s*["']([^"']*)["']/gi), (m) => decodeEntities(m[1]));
  const tels = new Set<string>();
  const mails = new Set<string>();
  let telBad = 0;
  let mailBad = 0;
  let zaloBad = 0;
  for (const h of hrefs) {
    const hl = h.toLowerCase().trim();
    if (hl.startsWith('tel:')) tels.add(h.trim().slice(4));
    else if (hl.startsWith('tel') && /^tel[^a-z]/.test(hl)) {
      telBad++;
      findings.push({
        type: 'call_link',
        severity: 'critical',
        message: `Call link "${short(h, 60)}" is missing the colon after “tel”, so tapping it does nothing.`,
      });
    } else if (hl.startsWith('mailto:')) mails.add(h.trim().slice(7));
    else if (hl.includes('zalo.me')) {
      const after = hl.split('zalo.me/').pop() || '';
      const num = after.split('?')[0].replace(/\D/g, '');
      const noNumber = /zalo\.me\/?$/.test(hl.replace(/[?#].*$/, ''));
      if (noNumber || (num && ![10, 11, 18, 19].includes(num.length))) {
        zaloBad++;
        findings.push({
          type: 'zalo_link',
          severity: 'critical',
          message: `Zalo link has no phone number (or an odd one), so customers can’t reach you: ${short(h, 80)}`,
        });
      }
    }
  }

  // Displayed number vs. dialed number
  for (const m of text.matchAll(/<a[^>]+href\s*=\s*["']tel:([^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    const shownText = stripTags(decodeEntities(m[2]));
    const shown = shownText.replace(/\D/g, '');
    const dialed = safeDecodeURI(decodeEntities(m[1])).replace(/\D/g, '');
    if (shown.length >= 9 && dialed.length >= 9 && shown.slice(-9) !== dialed.slice(-9)) {
      telBad++;
      findings.push({
        type: 'call_link',
        severity: 'critical',
        message: `The page shows "${short(shownText, 40)}" but tapping it calls ${short(safeDecodeURI(m[1]), 30)}: customers reach a different number.`,
      });
    }
  }

  for (const v of Array.from(tels).sort()) {
    const r = checkTel(v);
    if (r) {
      telBad++;
      findings.push({ type: 'call_link', severity: 'critical', message: `Call link "tel:${short(v, 50)}" is broken: ${r}.` });
    }
  }

  const emailDomains = new Set<string>();
  for (const v of Array.from(mails).sort()) {
    const [r, dom] = checkMailto(v);
    if (r) {
      mailBad++;
      findings.push({ type: 'email_link', severity: 'critical', message: `Email link "mailto:${short(v, 50)}" is broken: ${r}.` });
    } else if (dom) emailDomains.add(dom);
  }

  // Injected / spam links
  let host = '';
  try {
    host = new URL(base).hostname.replace(/^www\./, '');
  } catch {
    /* ignore */
  }
  const spamSeen = new Set<string>();
  for (const h of hrefs) {
    if (!/^https?:/i.test(h) || spamSeen.size >= 10) continue;
    let linkHost = '';
    try {
      linkHost = new URL(h).hostname;
    } catch {
      continue;
    }
    if (host && (linkHost === host || linkHost.endsWith('.' + host))) continue;
    if (SPAM_WORDS.test(safeDecodeURI(h)) && !spamSeen.has(h)) {
      spamSeen.add(h);
      findings.push({
        type: 'suspicious_link',
        severity: 'critical',
        message: `Suspicious link (gambling/pharma/adult/loan), possibly injected by a hack: ${short(h, 100)}`,
      });
    }
  }

  if (/lorem ipsum/i.test(text)) {
    findings.push({
      type: 'placeholder_text',
      severity: 'warning',
      message: 'The page source contains the sample text “Lorem ipsum”. Check whether it’s visible on the page.',
    });
  }

  const tm = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(text);
  const title = tm ? decodeEntities(tm[1]).replace(/\s+/g, ' ').trim() : '';
  if (!title || /^(home|home page|homepage|my store|mega shop|just another wordpress site|trang chủ|untitled|my wordpress|my blog|site title)$/i.test(title)) {
    findings.push({
      type: 'page_title',
      severity: 'warning',
      message: title
        ? `The page title is still a placeholder: "${short(title, 60)}". Google shows this title in search results.`
        : 'The page has no title. Google shows the title in search results.',
    });
  }

  const images: string[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(/<img[^>]+?(?:data-src|data-lazy-src|src)\s*=\s*["']([^"']+)["']/gi)) {
    const src = decodeEntities(m[1]).trim();
    if (!src || src.startsWith('data:')) continue;
    let abs: string;
    try {
      abs = new URL(src, base).toString();
    } catch {
      continue;
    }
    if (seen.has(abs)) continue;
    seen.add(abs);
    images.push(abs);
    if (images.length >= 40) break;
  }

  return {
    findings,
    title,
    images,
    telCount: tels.size,
    mailCount: mails.size,
    emailDomains: Array.from(emailDomains).sort(),
    telOk: telBad === 0,
    mailOk: mailBad === 0,
    zaloOk: zaloBad === 0,
    spamFree: spamSeen.size === 0,
  };
}

// ---------------------------------------------------------------------------
// MX records
// ---------------------------------------------------------------------------
/** true = has MX, false = definitely none, null = unknown (DNS error/timeout). */
export async function hasMx(domain: string): Promise<boolean | null> {
  const resolver = new dns.promises.Resolver({ timeout: 3000, tries: 2 });
  try {
    const mx = await resolver.resolveMx(domain);
    // RFC 7505 "null MX": a single record with an empty exchange means "no mail".
    return mx.some((r) => r.exchange && r.exchange !== '.');
  } catch (e) {
    const c = errCode(e);
    if (c === 'ENODATA' || c === 'ENOTFOUND' || c === dns.NODATA || c === dns.NOTFOUND) return false;
    return null;
  }
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------
function sameSite(a: string, b: string): boolean {
  const x = a.replace(/^www\./, '');
  const y = b.replace(/^www\./, '');
  return x === y || x.endsWith('.' + y) || y.endsWith('.' + x);
}

async function heavyImages(urls: string[], siteHost: string, deadline: number) {
  const candidates: string[] = [];
  for (const raw of urls) {
    if (candidates.length >= MAX_IMAGES) break;
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      continue;
    }
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && sameSite(u.hostname, siteHost))) continue;
    if (portProblem(u) || u.username || u.password || hostnameProblem(u.hostname)) continue;
    candidates.push(u.toString());
  }
  const heavy: { url: string; kb: number }[] = [];
  let skipped = 0;
  let i = 0;
  const worker = async () => {
    while (i < candidates.length) {
      const url = candidates[i++];
      if (deadline - Date.now() < 500) {
        skipped++;
        continue;
      }
      try {
        const r = await safeRequest(url, { method: 'HEAD', deadline });
        const len = parseInt(String(r.headers['content-length'] || '0'), 10);
        if (r.status < 400 && len > HEAVY_IMAGE_KB * 1024) heavy.push({ url, kb: Math.round(len / 1024) });
      } catch {
        /* unreachable image: ignore */
      }
    }
  };
  await Promise.all(Array.from({ length: 5 }, worker));
  heavy.sort((a, b) => b.kb - a.kb);
  return { heavy, checked: candidates.length - skipped, skipped };
}

// ---------------------------------------------------------------------------
// Main check
// ---------------------------------------------------------------------------
export type CheckResult = {
  host: string;
  checkedAt: string;
  status: number | null;
  responseMs: number | null;
  finalUrl: string | null;
  ssl: { ok: boolean; daysLeft: number | null; expires: string | null; error: string | null };
  issues: Finding[];
  warnings: Finding[];
  passed: { type: string; message: string }[];
  stats: {
    htmlKB: number | null;
    telLinks: number;
    mailLinks: number;
    heavyImages: { url: string; kb: number }[];
    imagesChecked: number;
  };
  partial: boolean;
  pageSpeedUrl: string;
  disclaimer: string;
};

const DISCLAIMER =
  'Link and text issues are detected from the page source (the HTML), so they may include hidden elements, such as a menu that only shows on mobile. Please double-check them in a browser. This check does not measure page speed; use Google PageSpeed Insights for that.';

function isCertError(e: unknown): boolean {
  const c = errCode(e);
  return (
    c.startsWith('CERT_') ||
    c.startsWith('ERR_TLS_CERT') ||
    c in SSL_MESSAGES ||
    /certificate/i.test(String((e as Error)?.message || ''))
  );
}

function fetchErrorMessage(e: unknown): string {
  const c = errCode(e);
  if (c === 'ENOTFOUND' || c === 'EAI_AGAIN') return 'The domain name doesn’t point to any server.';
  if (c === 'ETIMEDOUT') return 'The server didn’t answer within 10 seconds.';
  if (c === 'ECONNREFUSED') return 'The server refused the connection.';
  if (c === 'ECONNRESET') return 'The server closed the connection.';
  if (c === 'ETOOMANYREDIRECTS') return 'The website redirects too many times.';
  if (c === 'EBLOCKED') return 'The website redirected to an address that can’t be checked.';
  return 'The website could not be reached.';
}

const fmtDate = (iso: string | null) =>
  iso ? new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }) : '';

export async function runWebsiteCheck(rawUrl: unknown): Promise<CheckResult> {
  const { host, url } = normalizeInput(rawUrl);
  await assertPublicHost(host);
  const deadline = Date.now() + TOTAL_TIMEOUT_MS;
  const issues: Finding[] = [];
  const warnings: Finding[] = [];
  const passed: { type: string; message: string }[] = [];
  let partial = false;

  const sslPromise = checkSsl(host, deadline);

  // Fetch the home page: https first; if the certificate is bad, read it anyway (the SSL problem
  // is reported separately); if https is not served at all, fall back to http.
  let page: SafeResponse | null = null;
  let fetchError: unknown = null;
  try {
    page = await safeRequest(url, { deadline });
  } catch (e) {
    fetchError = e;
    const c = errCode(e);
    if (c !== 'EBLOCKED') {
      if (isCertError(e)) {
        try {
          page = await safeRequest(url, { deadline, insecure: true });
        } catch {
          /* fall through to http */
        }
      }
      if (!page && c !== 'ETIMEDOUT') {
        try {
          page = await safeRequest(`http://${host}/`, { deadline });
        } catch (e2) {
          if (errCode(e2) === 'EBLOCKED') fetchError = e2;
        }
      }
    }
  }
  if (errCode(fetchError) === 'EBLOCKED' && !page) {
    throw new CheckInputError('This website redirects to an address that can’t be checked.');
  }

  const ssl = await sslPromise;

  // --- Site up ---
  const status = page ? page.status : null;
  if (!page) {
    issues.push({ type: 'site_down', severity: 'critical', message: `Your website can’t be reached. ${fetchErrorMessage(fetchError)}` });
  } else if (page.status >= 500) {
    issues.push({ type: 'site_down', severity: 'critical', message: `The website shows a server error (HTTP ${page.status}). Visitors see an error page instead of your site.` });
  } else if (page.status >= 400) {
    issues.push({ type: 'site_down', severity: 'critical', message: `The home page returns an error (HTTP ${page.status}).` });
  }
  const text = page ? page.body.toString('utf8') : '';
  if (
    page &&
    (/defaultwebpage\.cgi|Default Web Site Page|Apache2 \w+ Default Page|domain is parked|This domain is parked|Welcome to nginx!/i.test(text.slice(0, 20000)) ||
      page.finalUrl.includes('defaultwebpage'))
  ) {
    issues.push({ type: 'site_down', severity: 'critical', message: 'The website shows the hosting company’s default page instead of your site.' });
  }
  if (page && page.status < 400 && !issues.some((i) => i.type === 'site_down')) {
    passed.push({ type: 'site_up', message: `Website is online (HTTP ${page.status}).` });
  }
  if (page) {
    if (page.ms > 5000) {
      warnings.push({ type: 'slow_server', severity: 'warning', message: `The server took ${(page.ms / 1000).toFixed(1)} seconds to send the home page. Visitors may leave before it loads.` });
    } else if (page.status < 400) {
      passed.push({ type: 'server_response', message: `Server responded in ${(page.ms / 1000).toFixed(1)} s.` });
    }
  }

  // --- SSL ---
  if (ssl.ok) {
    if (ssl.daysLeft !== null && ssl.daysLeft < 0) {
      issues.push({ type: 'ssl', severity: 'critical', message: `The SSL certificate expired on ${fmtDate(ssl.expires)}. Browsers show a “Not secure” warning.` });
    } else if (ssl.daysLeft !== null && ssl.daysLeft <= 14) {
      warnings.push({ type: 'ssl_expiring', severity: 'warning', message: `The SSL certificate expires in ${ssl.daysLeft} day${ssl.daysLeft === 1 ? '' : 's'} (${fmtDate(ssl.expires)}). If it isn’t renewed, browsers will show a “Not secure” warning.` });
    } else {
      passed.push({ type: 'ssl', message: `SSL certificate is valid${ssl.daysLeft !== null ? ` for ${ssl.daysLeft} more days (until ${fmtDate(ssl.expires)})` : ''}.` });
    }
  } else if (ssl.chainIncomplete) {
    warnings.push({ type: 'ssl_chain', severity: 'warning', message: 'The server is missing an intermediate SSL certificate. Desktop browsers usually still open the site, but some phones and apps may show a security error.' });
    if (ssl.daysLeft !== null && ssl.daysLeft <= 14) {
      (ssl.daysLeft < 0 ? issues : warnings).push({
        type: 'ssl_expiring',
        severity: ssl.daysLeft < 0 ? 'critical' : 'warning',
        message: ssl.daysLeft < 0 ? `The SSL certificate expired on ${fmtDate(ssl.expires)}.` : `The SSL certificate expires in ${ssl.daysLeft} days (${fmtDate(ssl.expires)}).`,
      });
    }
  } else {
    const when = ssl.code === 'CERT_HAS_EXPIRED' && ssl.expires ? ` It expired on ${fmtDate(ssl.expires)}.` : '';
    issues.push({ type: 'ssl', severity: 'critical', message: `${ssl.error}${when} Browsers show a “Not secure” warning and many visitors leave.` });
  }
  if (page && page.finalUrl.startsWith('http://') && ssl.ok) {
    warnings.push({ type: 'https_redirect', severity: 'warning', message: 'The website switches visitors from secure https:// to plain http:// even though the certificate is valid.' });
  }

  // --- Page content ---
  let htmlKB: number | null = null;
  let telLinks = 0;
  let mailLinks = 0;
  let heavy: { url: string; kb: number }[] = [];
  let imagesChecked = 0;
  if (page && page.body.length) {
    htmlKB = Math.round(page.body.length / 1024);
    const a = analyzeHtml(text, page.finalUrl);
    telLinks = a.telCount;
    mailLinks = a.mailCount;
    for (const f of a.findings) (f.severity === 'critical' ? issues : warnings).push(f);
    if (a.telCount && a.telOk) passed.push({ type: 'call_link', message: `${a.telCount} call link${a.telCount > 1 ? 's' : ''} look${a.telCount > 1 ? '' : 's'} correct.` });
    if (a.mailCount && a.mailOk) passed.push({ type: 'email_link', message: `${a.mailCount} email link${a.mailCount > 1 ? 's' : ''} look${a.mailCount > 1 ? '' : 's'} correct.` });
    if (!a.telCount && !a.mailCount) {
      warnings.push({ type: 'no_contact_links', severity: 'warning', message: 'No tap-to-call or tap-to-email links were found on the home page. On a phone, customers have to copy your number by hand.' });
    }
    if (a.spamFree) passed.push({ type: 'suspicious_link', message: 'No suspicious (gambling, pharma, adult) links found.' });
    if (!a.findings.some((f) => f.type === 'page_title')) passed.push({ type: 'page_title', message: `Page title is set: "${short(a.title, 60)}".` });

    // MX + images in parallel
    const domains = a.emailDomains.filter((d) => !WELL_KNOWN_MAIL.has(d)).slice(0, MAX_EMAIL_DOMAINS);
    const [mxResults, imgs] = await Promise.all([
      Promise.all(domains.map(async (d) => [d, await hasMx(d)] as const)),
      heavyImages(a.images, new URL(page.finalUrl).hostname, deadline),
    ]);
    const noMx = mxResults.filter(([, ok]) => ok === false).map(([d]) => d);
    for (const d of noMx) {
      issues.push({ type: 'email_domain', severity: 'critical', message: `The email domain “${d}” has no mail server (MX record), so emails sent to it will bounce.` });
    }
    if (mxResults.some(([, ok]) => ok === true) && !noMx.length) {
      passed.push({ type: 'email_domain', message: 'Email domain can receive mail (MX record found).' });
    }
    heavy = imgs.heavy.slice(0, 10);
    imagesChecked = imgs.checked;
    if (imgs.skipped) partial = true;
    if (imgs.heavy.length) {
      warnings.push({
        type: 'heavy_images',
        severity: 'warning',
        message: `${imgs.heavy.length} image${imgs.heavy.length > 1 ? 's are' : ' is'} over ${HEAVY_IMAGE_KB} KB (largest ${imgs.heavy[0].kb.toLocaleString('en-US')} KB). Large images make the page slow on mobile data.`,
      });
    } else if (imgs.checked) {
      passed.push({ type: 'heavy_images', message: `No images over ${HEAVY_IMAGE_KB} KB (${imgs.checked} checked).` });
    }
    if (page.truncated) {
      partial = true;
      warnings.push({ type: 'html_size', severity: 'warning', message: 'The home page HTML is over 2 MB, which is very heavy. Only the first 2 MB were checked.' });
    } else if (htmlKB > 500) {
      warnings.push({ type: 'html_size', severity: 'warning', message: `The home page HTML is ${htmlKB} KB, which is heavy (under 200 KB is typical).` });
    }
  }

  return {
    host,
    checkedAt: new Date().toISOString(),
    status,
    responseMs: page ? page.ms : null,
    finalUrl: page ? page.finalUrl : null,
    ssl: { ok: ssl.ok && (ssl.daysLeft ?? 0) >= 0, daysLeft: ssl.daysLeft, expires: ssl.expires, error: ssl.error },
    issues,
    warnings,
    passed,
    stats: { htmlKB, telLinks, mailLinks, heavyImages: heavy, imagesChecked },
    partial,
    pageSpeedUrl: `https://pagespeed.web.dev/analysis?url=${encodeURIComponent(`https://${host}/`)}`,
    disclaimer: DISCLAIMER,
  };
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------
// NOTE: these limits live in memory, so they are per server instance. On Vercel each
// serverless instance has its own counters and they reset on cold start; this is a cheap
// abuse brake, not a hard guarantee. Use a shared store (e.g. Upstash/Redis) for strict limits.
export const RATE_WINDOW_MS = 10 * 60 * 1000;
export const RATE_PER_IP = 5;
export const RATE_GLOBAL = 100;
export const MAX_CONCURRENT = 8;

const ipHits = new Map<string, number[]>();
let globalHits: number[] = [];
let inFlight = 0;

export function takeRateLimit(ip: string, now = Date.now()): { ok: true } | { ok: false; retryAfterSec: number; scope: 'ip' | 'global' } {
  const cutoff = now - RATE_WINDOW_MS;
  globalHits = globalHits.filter((t) => t > cutoff);
  if (ipHits.size > 5000) {
    for (const [k, v] of ipHits) if (!v.some((t) => t > cutoff)) ipHits.delete(k);
  }
  const hits = (ipHits.get(ip) || []).filter((t) => t > cutoff);
  if (hits.length >= RATE_PER_IP) {
    ipHits.set(ip, hits);
    return { ok: false, scope: 'ip', retryAfterSec: Math.ceil((hits[0] + RATE_WINDOW_MS - now) / 1000) };
  }
  if (globalHits.length >= RATE_GLOBAL) {
    return { ok: false, scope: 'global', retryAfterSec: Math.ceil((globalHits[0] + RATE_WINDOW_MS - now) / 1000) };
  }
  hits.push(now);
  ipHits.set(ip, hits);
  globalHits.push(now);
  return { ok: true };
}

export function acquireSlot(): boolean {
  if (inFlight >= MAX_CONCURRENT) return false;
  inFlight++;
  return true;
}

export function releaseSlot(): void {
  inFlight = Math.max(0, inFlight - 1);
}
