# Free Website Health Check

Checks a public website for: uptime / hosting default page, SSL certificate expiry, call (`tel:`), Zalo and email (`mailto:`) links, email-domain MX records, placeholder titles, injected spam links, heavy images and page HTML size.

- **Front end:** `index.html`, static, served by GitHub Pages: https://nguyenthong251.github.io/website-health-check/
- **API:** `api/check.ts` (Vercel Node.js function) using `lib/check.ts`: `POST /api/check {"url":"example.com"}`

## Security
The API fetches URLs from anonymous visitors, so every request goes through an SSRF guard (public DNS names only, every resolved IP must be public, re-checked at connect time, max 3 redirects each re-validated, timeouts and a body cap). Rate limits: 5 checks per IP and 100 in total per 10 minutes, 8 concurrent (in memory, per instance). CORS is limited to the GitHub Pages origin, the Vercel domain and localhost. Submitted URLs are not stored or logged.

## Deploy
- GitHub Pages: branch `main`, root.
- Vercel: import this repo (framework preset "Other"); the function is picked up from `api/`. If the Vercel domain is not `website-health-check.vercel.app`, update `API` in `index.html`.
