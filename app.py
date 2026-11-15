"""TenantPost — a working prototype of tenant email delivery for a
tour-operator CRM.

Honest labelling: this is a demo built as a work sample. It is NOT a
production system and NOT the product of any CRM company. The DNS tools
perform real lookups; the test-send lane only sends when a real ZeptoMail
API key is configured via the ZEPTOMAIL_API_KEY environment variable.

Run locally:  flask --app app run   (or: gunicorn app:app)
"""

from __future__ import annotations

import json
import os

import requests
from flask import Flask, render_template, request

import dns_tools

app = Flask(__name__)

ZEPTOMAIL_ENDPOINT = "https://api.zeptomail.com/v1.1/email"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


@app.route("/wizard", methods=["GET", "POST"])
def wizard():
    context: dict = {"domain": "", "generated": None, "verification": None,
                     "error": None}
    if request.method == "POST":
        domain = dns_tools.normalize_domain(request.form.get("domain", ""))
        context["domain"] = domain
        if not dns_tools.is_plausible_domain(domain):
            context["error"] = (
                "That doesn't look like a domain. Enter something like "
                "sunnycycletours.com (a bare domain, an email address, or a "
                "URL all work)."
            )
        else:
            context["generated"] = dns_tools.generated_tenant_records(domain)
            context["verification"] = _wizard_verification(domain)
    return render_template("wizard.html", **context)


def _wizard_verification(domain: str) -> list[dict]:
    """Live-check whether the wizard's records already exist for *domain*."""
    sending = f"mail.{domain}"
    rows: list[dict] = []

    def row(label: str, values: list[str], expected_hint: str) -> None:
        rows.append({
            "label": label,
            "found": bool(values),
            "records_found": values,
            "hint": expected_hint,
        })

    row(f"SPF on {domain}", dns_tools.spf_records(domain),
        "v=spf1 … — authorises senders for the root domain")
    row(f"SPF on {sending}", dns_tools.spf_records(sending),
        "v=spf1 include:spf.zeptomail.com ~all — the record this wizard generates")
    dmarc = dns_tools.dmarc_record(domain)
    row(f"DMARC on _dmarc.{domain}", [dmarc] if dmarc else [],
        "v=DMARC1; p=… — the domain's anti-spoofing policy")
    dkim = dns_tools.dkim_records(domain)
    row("DKIM key (common selectors)",
        [f"{item['selector']}._domainkey: {item['record']}" for item in dkim],
        "v=DKIM1; k=rsa; p=… — a published signing key")
    return rows


@app.route("/checker", methods=["GET", "POST"])
def checker():
    context: dict = {"domain": "", "report": None, "error": None}
    if request.method == "POST":
        domain = dns_tools.normalize_domain(request.form.get("domain", ""))
        context["domain"] = domain
        if not dns_tools.is_plausible_domain(domain):
            context["error"] = (
                "That doesn't look like a domain. Enter something like "
                "google.com (a bare domain, an email address, or a URL all work)."
            )
        else:
            context["report"] = dns_tools.build_report(domain)
    return render_template("checker.html", **context)


def _zepto_auth_header(key: str) -> str:
    key = key.strip()
    return key if " " in key else f"Zoho-enczapikey {key}"


@app.route("/test-send", methods=["GET", "POST"])
def test_send():
    api_key = os.environ.get("ZEPTOMAIL_API_KEY", "").strip()
    context: dict = {
        "configured": bool(api_key),
        "result": None,
        "payload_preview": None,
        "form": {"from_name": "", "from_address": "", "to_address": "",
                 "subject": "", "body": ""},
    }
    if request.method == "POST":
        form = {field: request.form.get(field, "").strip()
                for field in context["form"]}
        context["form"] = form
        payload = {
            "from": {"address": form["from_address"], "name": form["from_name"]},
            "to": [{"email_address": {"address": form["to_address"], "name": ""}}],
            "subject": form["subject"],
            "textbody": form["body"],
        }
        if not api_key:
            # Honest not-configured state: nothing is sent, ever, without a key.
            context["payload_preview"] = json.dumps(
                {"POST": ZEPTOMAIL_ENDPOINT, "body": payload}, indent=2)
        else:
            try:
                response = requests.post(
                    ZEPTOMAIL_ENDPOINT,
                    json=payload,
                    headers={
                        "Authorization": _zepto_auth_header(api_key),
                        "Content-Type": "application/json",
                    },
                    timeout=20,
                )
                context["result"] = {
                    "ok": response.status_code in (200, 201),
                    "status_code": response.status_code,
                    "body": response.text[:2000],
                }
            except requests.RequestException as exc:
                context["result"] = {
                    "ok": False,
                    "status_code": None,
                    "body": f"The API call itself failed: {exc}",
                }
    return render_template("test_send.html", **context)


@app.route("/option-two")
def option_two():
    return render_template("option_two.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
