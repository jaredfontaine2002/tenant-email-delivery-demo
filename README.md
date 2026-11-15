# TenantPost — tenant email delivery prototype

A working prototype of the two tenant sending options for a tour-operator CRM,
built as a **work sample**. It exists to demonstrate, with live tools rather
than slides, how a CRM for small tour operators (starting with self-guided
cycling tour companies) can stop its tenant email landing in spam.

## Honest labelling — read this first

- This is a **prototype / demo**. It is not a production system, it is not
  affiliated with any CRM company, and it must never be presented as either.
- The DNS tools perform **real, live lookups** (via `dnspython`) and report
  whatever public DNS actually returns. Nothing is cached, mocked, or stored.
- The **test-send lane never fakes a result**. Without a ZeptoMail API key it
  states plainly that sending is not configured and shows the exact API
  request it *would* make. With a key, it makes the real API call and shows
  the real response, success or error.
- The **DKIM value in the setup wizard is a labelled example placeholder**.
  In production, the email provider generates a unique key pair per tenant
  and supplies the real public key at onboarding.
- The **option-two page is a design document**, labelled as such — it is not
  a working feature.
- There is deliberately **no database**. The tools are stateless, so the
  prototype uses no persistence rather than faking a data layer it does not
  need. (The production stack this mirrors pairs the Flask back end with
  Postgres; tenant records, OAuth tokens, and DNS-verification state would
  live there in a real build.)

## What each page does

| Page | What it does |
| --- | --- |
| `/` | Overview: the spam problem, the two sending options, and links to the tools. |
| `/wizard` | **Option one onboarding.** Enter a tenant domain → the app generates the exact SPF, DKIM and DMARC TXT records to publish (sending from a `mail.` subdomain), then runs live DNS verification of what already exists for that domain. |
| `/checker` | **Deliverability report card.** Live checks for any domain — MX, SPF presence/uniqueness, SPF DNS-lookup count vs the RFC 7208 limit of 10, SPF `all` policy strength, DMARC presence and enforcement policy, DKIM under common selectors — each graded pass/warn/fail with a plain-English explanation of what it means for spam placement. DKIM "not found" always carries the caveat that keys can live under custom selector names. |
| `/test-send` | A send form wired to the ZeptoMail API (`POST https://api.zeptomail.com/v1.1/email`). Key configured → real send, real response shown. No key → honest not-configured notice plus a preview of the exact request payload. |
| `/option-two` | **Design page** for the "send from any address, no integration" lane: why sending as the tenant from platform servers fails SPF/DKIM alignment and DMARC, and the legitimate architecture — sending through the tenant's own mailbox via Google/Microsoft OAuth (Gmail API / Microsoft Graph) — with its constraints (consent/revocation, mailbox sending quotas, provider app review, and the honestly-labelled platform-domain fallback). |

## Stack

- Python 3.12 + Flask 3, served by gunicorn
- `dnspython` for live DNS lookups, `requests` for the ZeptoMail API call
- Plain HTML/CSS (Jinja templates, one stylesheet, no JS framework) —
  mirroring the Python/Flask server side of the CRM stack it models
  (React front end, Flask back end, Postgres, ZeptoMail, in production)

## Run it locally

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# DNS tools only (no key needed):
flask --app app run            # http://127.0.0.1:5000

# With the live send lane enabled:
ZEPTOMAIL_API_KEY="Zoho-enczapikey <your-send-mail-token>" flask --app app run
```

Or with gunicorn, as in production: `gunicorn app:app`.

## Deploy on Render

A `render.yaml` blueprint is included:

1. Push this repo to GitHub/GitLab and choose **New → Blueprint** in Render,
   or create a Web Service manually with:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
   - Health check path: `/healthz`
2. (Optional) Set `ZEPTOMAIL_API_KEY` in the service's Environment tab to
   enable real test sends. It is declared `sync: false` in `render.yaml`,
   so the value is entered in the dashboard and never committed to the repo.
   Without it, everything except actual sending works, and the test-send
   page says so honestly.
3. The free plan is fine for a demo; note that free services sleep when idle,
   so the first load after a quiet period can take up to a minute.

## Why these two options are the whole problem

DMARC requires SPF or DKIM to pass **and align** with the visible From
domain. Option one gives the platform that alignment properly, through the
tenant's own DNS. Option two cannot be faked from platform servers — the
only honest route is the tenant's own connected mailbox. Everything in this
demo is built around that single fact.
