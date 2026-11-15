"""Live DNS diagnostics for email authentication (SPF / DKIM / DMARC / MX).

Everything in this module performs *real* DNS lookups with dnspython.
Nothing is simulated: if a record is reported as found, it was returned by
a live query; if it is reported missing, the query returned no usable answer.
"""

from __future__ import annotations

import re

import dns.exception
import dns.resolver

# Selectors probed for DKIM. A domain can use any selector name, so "not found"
# here only means "not found under the common selectors we check" -- the UI
# states that caveat wherever this result is shown.
COMMON_DKIM_SELECTORS = [
    "default",
    "zepto",
    "zoho",
    "google",
    "selector1",
    "selector2",
    "mail",
    "s1",
    "s2",
    "dkim",
    "k1",
    "smtp",
    "mandrill",
]

_RESOLVER = dns.resolver.Resolver()
_RESOLVER.lifetime = 6.0

_DNS_ERRORS = (
    dns.resolver.NoAnswer,
    dns.resolver.NXDOMAIN,
    dns.resolver.NoNameservers,
    dns.resolver.NoResolverConfiguration,
    dns.exception.Timeout,
)


def normalize_domain(raw: str) -> str:
    """Turn whatever a user pasted (URL, email address, domain) into a domain."""
    value = (raw or "").strip().lower()
    if "@" in value:  # an email address was pasted -- keep the domain part
        value = value.rsplit("@", 1)[-1]
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.strip().strip(".")
    return value


def is_plausible_domain(value: str) -> bool:
    return bool(re.fullmatch(r"(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}", value or ""))


def txt_records(name: str) -> list[str]:
    """All TXT strings at *name* (multi-string records joined), [] if none."""
    try:
        answers = _RESOLVER.resolve(name, "TXT")
    except _DNS_ERRORS:
        return []
    records: list[str] = []
    for rdata in answers:
        parts = [
            chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else str(chunk)
            for chunk in rdata.strings
        ]
        records.append("".join(parts))
    return records


def mx_records(domain: str) -> list[dict]:
    """MX records for *domain* as [{'preference': int, 'host': str}, ...]."""
    try:
        answers = _RESOLVER.resolve(domain, "MX")
    except _DNS_ERRORS:
        return []
    out = [
        {"preference": r.preference, "host": str(r.exchange).rstrip(".")}
        for r in answers
    ]
    return sorted(out, key=lambda item: item["preference"])


def spf_records(domain: str) -> list[str]:
    return [r for r in txt_records(domain) if r.lower().startswith("v=spf1")]


def dmarc_record(domain: str) -> str | None:
    for record in txt_records(f"_dmarc.{domain}"):
        if "v=dmarc1" in record.lower():
            return record
    return None


def parse_dmarc(record: str) -> dict:
    """Pull the interesting tags out of a DMARC record string."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            key, _, val = part.partition("=")
            tags[key.strip().lower()] = val.strip()
    return {
        "policy": tags.get("p", "").lower(),
        "subdomain_policy": tags.get("sp", "").lower(),
        "pct": tags.get("pct", "100"),
        "rua": tags.get("rua", ""),
        "raw": record,
    }


def dkim_records(domain: str, selectors: list[str] | None = None) -> list[dict]:
    """DKIM records found under common selectors.

    Returns [{'selector': str, 'record': str}, ...]. Empty means no key was
    found *under the selectors checked* -- not proof a domain has no DKIM.
    """
    found: list[dict] = []
    for selector in selectors or COMMON_DKIM_SELECTORS:
        for record in txt_records(f"{selector}._domainkey.{domain}"):
            lowered = record.lower()
            if "v=dkim1" in lowered or "p=" in lowered:
                found.append({"selector": selector, "record": record})
    return found


def _spf_lookup_count(record: str, depth: int = 0, seen: set | None = None) -> int:
    """Estimate the DNS-lookup count of an SPF record (RFC 7208 limit is 10).

    Counts include/a/mx/ptr/exists mechanisms and redirect modifiers, and
    follows includes/redirects recursively (bounded) so nested providers are
    counted too. ip4/ip6 mechanisms cost no lookup and are ignored.
    """
    if seen is None:
        seen = set()
    count = 0
    for token in record.split():
        mech = token.lower().lstrip("+-~?")
        if mech.startswith("include:"):
            count += 1
            target = mech.split(":", 1)[1]
            if depth < 3 and target not in seen:
                seen.add(target)
                for nested in spf_records(target):
                    count += _spf_lookup_count(nested, depth + 1, seen)
        elif mech.startswith("redirect="):
            count += 1
            target = mech.split("=", 1)[1]
            if depth < 3 and target not in seen:
                seen.add(target)
                for nested in spf_records(target):
                    count += _spf_lookup_count(nested, depth + 1, seen)
        elif (
            mech == "a"
            or mech.startswith("a:")
            or mech.startswith("a/")
            or mech == "mx"
            or mech.startswith("mx:")
            or mech.startswith("mx/")
            or mech == "ptr"
            or mech.startswith("ptr:")
            or mech.startswith("exists:")
        ):
            count += 1
    return count


def spf_all_qualifier(record: str) -> str | None:
    """The qualifier on the terminal 'all' mechanism, e.g. '-all' / '~all'."""
    for token in record.split():
        lowered = token.lower()
        if lowered in ("all", "+all", "-all", "~all", "?all"):
            return lowered if lowered.startswith(("+", "-", "~", "?")) else "?all"
    return None


def audit_domain(domain: str) -> dict:
    """Run every live check for *domain* and return structured raw results."""
    spf = spf_records(domain)
    dmarc_raw = dmarc_record(domain)
    return {
        "domain": domain,
        "mx": mx_records(domain),
        "spf_records": spf,
        "spf_lookup_count": _spf_lookup_count(spf[0]) if len(spf) == 1 else None,
        "spf_all": spf_all_qualifier(spf[0]) if spf else None,
        "dmarc": parse_dmarc(dmarc_raw) if dmarc_raw else None,
        "dkim": dkim_records(domain),
        "dkim_selectors_checked": COMMON_DKIM_SELECTORS,
    }


def build_report(domain: str) -> dict:
    """Audit *domain* and grade each check for the report card UI.

    Each check: {name, status: pass|warn|fail, detail, explanation}.
    """
    audit = audit_domain(domain)
    checks: list[dict] = []

    # --- MX ---------------------------------------------------------------
    if audit["mx"]:
        hosts = ", ".join(f"{m['host']} (pref {m['preference']})" for m in audit["mx"])
        checks.append({
            "name": "Mail exchangers (MX)",
            "status": "pass",
            "detail": hosts,
            "explanation": "The domain can receive mail. Not strictly required to "
                           "send, but a sending domain with no MX looks unfinished "
                           "to spam filters and cannot receive bounces or replies.",
        })
    else:
        checks.append({
            "name": "Mail exchangers (MX)",
            "status": "warn",
            "detail": "No MX records found.",
            "explanation": "The domain cannot receive mail. For a CRM tenant this "
                           "usually means replies and bounce notices have nowhere "
                           "to go, which quietly hurts sender reputation.",
        })

    # --- SPF presence / uniqueness ---------------------------------------
    spf = audit["spf_records"]
    if not spf:
        checks.append({
            "name": "SPF record",
            "status": "fail",
            "detail": "No SPF record found.",
            "explanation": "SPF tells receiving servers which senders may use this "
                           "domain. Without it, anyone can spoof the domain and "
                           "legitimate mail has no way to prove it is authorised -- "
                           "a direct route to the spam folder.",
        })
    elif len(spf) > 1:
        checks.append({
            "name": "SPF record",
            "status": "fail",
            "detail": f"{len(spf)} separate SPF records found.",
            "explanation": "A domain may only publish ONE SPF record. With two or "
                           "more, receivers return a permanent error (PermError) and "
                           "treat the mail as unauthenticated -- often worse than "
                           "having no SPF at all.",
        })
    else:
        checks.append({
            "name": "SPF record",
            "status": "pass",
            "detail": spf[0],
            "explanation": "One SPF record is published, so receiving servers can "
                           "check whether a sender is authorised to use this domain.",
        })

    # --- SPF lookup count --------------------------------------------------
    if len(spf) == 1 and audit["spf_lookup_count"] is not None:
        count = audit["spf_lookup_count"]
        if count > 10:
            checks.append({
                "name": "SPF DNS lookup count",
                "status": "fail",
                "detail": f"~{count} lookups (limit is 10).",
                "explanation": "SPF allows at most 10 DNS lookups per check. Over "
                               "the limit, validation fails with PermError and mail "
                               "is treated as unauthenticated, however good the "
                               "intentions were.",
            })
        elif count >= 8:
            checks.append({
                "name": "SPF DNS lookup count",
                "status": "warn",
                "detail": f"~{count} lookups (limit is 10).",
                "explanation": "Within the 10-lookup limit, but close. Adding one "
                               "more email provider's include could push it over and "
                               "break SPF entirely.",
            })
        else:
            checks.append({
                "name": "SPF DNS lookup count",
                "status": "pass",
                "detail": f"~{count} lookups (limit is 10).",
                "explanation": "Comfortably within the 10-lookup SPF limit, so SPF "
                               "validation completes instead of erroring out.",
            })

    # --- SPF 'all' strength -------------------------------------------------
    if len(spf) == 1 and audit["spf_all"]:
        qualifier = audit["spf_all"]
        if qualifier == "+all":
            checks.append({
                "name": "SPF policy strength",
                "status": "fail",
                "detail": "Record ends in +all.",
                "explanation": "+all authorises EVERY server on the internet to "
                               "send as this domain. SPF becomes meaningless and "
                               "spoofing is trivially easy.",
            })
        elif qualifier == "?all":
            checks.append({
                "name": "SPF policy strength",
                "status": "warn",
                "detail": "Record ends in ?all (neutral).",
                "explanation": "A neutral policy makes no statement about other "
                               "senders, so receivers give the domain little "
                               "protection against spoofing.",
            })
        elif qualifier == "~all":
            checks.append({
                "name": "SPF policy strength",
                "status": "pass",
                "detail": "Record ends in ~all (softfail).",
                "explanation": "Unauthorised senders are flagged as softfail. This "
                               "is the common production setting; -all is stricter "
                               "still.",
            })
        else:  # -all
            checks.append({
                "name": "SPF policy strength",
                "status": "pass",
                "detail": "Record ends in -all (fail).",
                "explanation": "The strictest setting: any sender not listed is "
                               "rejected as unauthorised. Best protection against "
                               "spoofing when the record is complete.",
            })

    # --- DMARC --------------------------------------------------------------
    dmarc = audit["dmarc"]
    if not dmarc:
        checks.append({
            "name": "DMARC record",
            "status": "fail",
            "detail": "No DMARC record found at _dmarc." + domain + ".",
            "explanation": "DMARC ties SPF and DKIM to the visible From domain and "
                           "tells receivers what to do when checks fail. Without it, "
                           "the domain has no anti-spoofing policy and no reporting "
                           "-- Gmail and Yahoo bulk-sender rules expect one.",
        })
    else:
        checks.append({
            "name": "DMARC record",
            "status": "pass",
            "detail": dmarc["raw"],
            "explanation": "A DMARC policy is published, so receivers can enforce "
                           "alignment between the From domain and SPF/DKIM results.",
        })
        policy = dmarc["policy"]
        if policy == "reject":
            checks.append({
                "name": "DMARC enforcement",
                "status": "pass",
                "detail": "Policy p=reject.",
                "explanation": "Full enforcement: mail that fails DMARC is "
                               "rejected outright. The strongest protection a "
                               "domain can publish.",
            })
        elif policy == "quarantine":
            checks.append({
                "name": "DMARC enforcement",
                "status": "pass",
                "detail": "Policy p=quarantine.",
                "explanation": "Mail that fails DMARC is sent to spam rather than "
                               "delivered. Real enforcement, one step below reject.",
            })
        else:
            checks.append({
                "name": "DMARC enforcement",
                "status": "warn",
                "detail": f"Policy p={policy or 'none'} (monitoring only).",
                "explanation": "p=none only collects reports -- failing mail is "
                               "still delivered. Fine while a tenant is setting up, "
                               "but it should ramp to quarantine, then reject, once "
                               "legitimate senders are aligned.",
            })

    # --- DKIM ----------------------------------------------------------------
    dkim = audit["dkim"]
    if dkim:
        found = ", ".join(item["selector"] for item in dkim)
        checks.append({
            "name": "DKIM signing key",
            "status": "pass",
            "detail": f"Key found under selector(s): {found}.",
            "explanation": "A DKIM public key is published, so receivers can verify "
                           "the cryptographic signature on mail from this domain. "
                           "DKIM that survives forwarding is a strong positive "
                           "signal for inbox placement.",
        })
    else:
        checked = ", ".join(audit["dkim_selectors_checked"])
        checks.append({
            "name": "DKIM signing key",
            "status": "warn",
            "detail": "No key found under the common selectors checked.",
            "explanation": "We probed these selectors: " + checked + ". DKIM may "
                           "still exist under a custom selector name, but if mail "
                           "is genuinely unsigned, it loses the authentication "
                           "signal that survives forwarding -- and DMARC can then "
                           "only pass via SPF.",
        })

    tallies = {"pass": 0, "warn": 0, "fail": 0}
    for check in checks:
        tallies[check["status"]] += 1
    if tallies["fail"]:
        verdict = (
            "This domain has authentication gaps that will land CRM mail in spam. "
            "Fix the failing checks first -- they are listed in plain English below."
        )
    elif tallies["warn"]:
        verdict = (
            "The basics are in place, but there are warnings worth fixing before "
            "sending customer mail at volume."
        )
    else:
        verdict = (
            "This domain's email authentication looks healthy. Its CRM mail has the "
            "SPF, DKIM and DMARC foundation inbox placement depends on."
        )
    return {"domain": domain, "checks": checks, "tallies": tallies,
            "verdict": verdict, "audit": audit}


def generated_tenant_records(domain: str) -> dict:
    """The DNS records a tenant publishes for own-domain sending (option one).

    Values follow the ZeptoMail-style onboarding pattern. The DKIM public key
    is a clearly-labelled EXAMPLE placeholder: in production the provider
    generates a unique key pair per tenant and supplies the real value.
    """
    sending_host = f"mail.{domain}"
    return {
        "sending_subdomain": sending_host,
        "records": [
            {
                "purpose": "SPF — authorise the provider to send for the "
                           "sending subdomain",
                "host": sending_host,
                "type": "TXT",
                "value": "v=spf1 include:spf.zeptomail.com ~all",
                "note": "Sending from a dedicated subdomain (mail.) keeps the "
                        "CRM's reputation separate from the tenant's main "
                        "domain mail.",
            },
            {
                "purpose": "DKIM — let the provider cryptographically sign "
                           "every message",
                "host": f"zepto._domainkey.{domain}",
                "type": "TXT",
                "value": "v=DKIM1; k=rsa; p=EXAMPLE-PLACEHOLDER-KEY",
                "note": "EXAMPLE VALUE: in production the provider generates a "
                        "unique key pair for each tenant and supplies the real "
                        "public key to paste here. Never share or reuse another "
                        "tenant's key.",
            },
            {
                "purpose": "DMARC — publish the domain's anti-spoofing policy "
                           "and collect reports",
                "host": f"_dmarc.{domain}",
                "type": "TXT",
                "value": f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; fo=1",
                "note": "Start at p=none (monitoring) while reports confirm "
                        "every legitimate sender is aligned, then ramp to "
                        "p=quarantine and finally p=reject.",
            },
        ],
    }
