# Email Verification, Disposable Domain, MX/SPF/DMARC & Fraud Risk Scoring API

Zero-cost, sub-50ms global edge API running on Cloudflare Workers using Cloudflare DNS-over-HTTPS (`https://cloudflare-dns.com/dns-query`). Built for RapidAPI Hub monetization.

## Endpoints
- `GET /v1/verify?email=support@expensify.com`: Full RFC 5322 syntax, disposable domain, role account, MX, SPF, DMARC, and 0-100 fraud risk score.
- `POST /v1/verify`: Single email verification via JSON body `{ "email": "..." }`.
- `POST /v1/verify-batch`: Parallel verification of up to 50 emails per request `{ "emails": ["..."] }`.
- `GET /v1/health`: Service status and edge region.
