/**
 * POST /api/check  { "url": "example.com" }  ->  CheckResult JSON
 *
 * Vercel Node.js function. The static front end (index.html) is served from GitHub Pages and
 * calls this endpoint cross-origin, so only the origins listed in ALLOWED_ORIGINS get CORS
 * headers; browser requests from any other site are refused. Rate limits are in memory, i.e.
 * per function instance (see lib/check.ts).
 *
 * Privacy: the submitted URL is never stored or logged by this handler.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { CheckInputError, acquireSlot, releaseSlot, runWebsiteCheck, takeRateLimit } from '../lib/check';

export const config = { maxDuration: 30 };

const ALLOWED_ORIGINS = [
  /^https:\/\/nguyenthong251\.github\.io$/,
  /^https:\/\/website-health-check[a-z0-9-]*\.vercel\.app$/,
  /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/,
];
const MAX_BODY = 2000;

type Req = IncomingMessage & { body?: unknown };

function send(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

function clientIp(req: Req): string {
  // On Vercel, x-real-ip / x-forwarded-for are set by the platform.
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real) return real.trim();
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd) return fwd.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

async function readUrl(req: Req): Promise<unknown> {
  const len = Number(req.headers['content-length'] || 0);
  if (len > MAX_BODY) throw new CheckInputError('Request too large.', 413);
  let raw: unknown = req.body;
  if (raw === undefined) {
    // Not pre-parsed (local dev server): read the stream ourselves, capped.
    raw = await new Promise<string>((resolve, reject) => {
      let data = '';
      req.setEncoding('utf8');
      req.on('data', (c: string) => {
        data += c;
        if (data.length > MAX_BODY) {
          reject(new CheckInputError('Request too large.', 413));
          req.destroy();
        }
      });
      req.on('end', () => resolve(data));
      req.on('error', reject);
    });
  }
  if (typeof raw === 'string') {
    if (raw.length > MAX_BODY) throw new CheckInputError('Request too large.', 413);
    try {
      raw = JSON.parse(raw);
    } catch {
      throw new CheckInputError('Please enter a website address.', 400);
    }
  }
  return (raw as { url?: unknown } | null)?.url;
}

export default async function handler(req: Req, res: ServerResponse) {
  const origin = typeof req.headers.origin === 'string' ? req.headers.origin : '';
  const allowed = ALLOWED_ORIGINS.some((r) => r.test(origin));
  if (origin && !allowed) return send(res, 403, { error: 'This checker can only be used from its own page.' });
  if (allowed) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '600');
    res.statusCode = 204;
    return res.end();
  }
  if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed.' }, { Allow: 'POST, OPTIONS' });

  const rl = takeRateLimit(clientIp(req));
  if (!rl.ok) {
    const minutes = Math.max(1, Math.ceil(rl.retryAfterSec / 60));
    return send(
      res,
      429,
      {
        error:
          rl.scope === 'ip'
            ? `You’ve run a few checks already. Please try again in about ${minutes} minute${minutes > 1 ? 's' : ''}.`
            : 'The checker is busy right now. Please try again in a few minutes.',
      },
      { 'Retry-After': String(rl.retryAfterSec) },
    );
  }

  let url: unknown;
  try {
    url = await readUrl(req);
  } catch (e) {
    if (e instanceof CheckInputError) return send(res, e.status, { error: e.message });
    return send(res, 400, { error: 'Please enter a website address.' });
  }

  if (!acquireSlot()) {
    return send(res, 429, { error: 'The checker is busy right now. Please try again in a minute.' }, { 'Retry-After': '60' });
  }
  try {
    return send(res, 200, await runWebsiteCheck(url));
  } catch (e) {
    if (e instanceof CheckInputError) return send(res, e.status, { error: e.message });
    console.error('website-check failed:', e instanceof Error ? e.name : 'unknown error');
    return send(res, 500, { error: 'Something went wrong while checking. Please try again.' });
  } finally {
    releaseSlot();
  }
}
