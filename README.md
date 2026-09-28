# h93lab report intake

One Cloudflare Worker for in-app reports from every h93lab app:
`POST https://report.h93lab.com/<app>/v1/report` (HLLM: `/hllm/v1/report`).

- Only app ids in `APPS` (index.ts) are accepted; add a project there.
- Stores only category, app version, OS and the user's opted-in text/note under
  `report:<app>:<time>-<uuid>` (90-day TTL). Never keys or chat history.
- Rate limit: 10 reports/hour per IP per app; the IP is only kept as a salted,
  daily-rotated hash (`RATE_SALT` secret, required).
