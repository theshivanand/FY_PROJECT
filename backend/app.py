from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse, parse_qs, unquote
import re

app = Flask(__name__)
CORS(app)

# ══════════════════════════════════════════════════════════════
#  SECTION 7 — WHITELIST
#  These exact registered domains are considered trusted when
#  accessed over https://. Keyword / brand-impersonation checks
#  are skipped for them (protocol check still applies).
# ══════════════════════════════════════════════════════════════
WHITELIST_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "instagram.com", "linkedin.com", "microsoft.com", "apple.com",
    "amazon.com", "paypal.com", "netflix.com", "github.com",
    "stackoverflow.com", "wikipedia.org", "reddit.com", "spotify.com",
    "adobe.com", "dropbox.com", "discord.com", "whatsapp.com"
}

# ══════════════════════════════════════════════════════════════
#  SECTION 3C — HIGH-RISK TLDs
# ══════════════════════════════════════════════════════════════
HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "loan",
    "work", "party", "racing", "win", "download", "stream", "gdn"
}
WATCHLIST_TLDS = {"info", "biz"}

# ══════════════════════════════════════════════════════════════
#  SECTION 4A — PHISHING KEYWORD LISTS
# ══════════════════════════════════════════════════════════════
FINANCIAL_KEYWORDS = [
    "bank", "banking", "wire", "transfer", "payment", "invoice",
    "billing", "credit", "debit", "card", "wallet", "crypto",
    "bitcoin", "ethereum"
]
ACTION_KEYWORDS = [
    "login", "signin", "signup", "verify", "verification", "validate",
    "confirm", "authenticate", "authorize", "reset", "recover",
    "unlock", "suspend", "reactivate"
]
URGENCY_KEYWORDS = [
    "urgent", "immediate", "alert", "warning", "important", "action",
    "required", "expire", "limited", "suspended", "blocked"
]
REWARD_KEYWORDS = [
    "free", "prize", "winner", "lucky", "reward", "gift", "bonus",
    "offer", "claim", "congratulations", "selected", "chosen"
]
SUPPORT_KEYWORDS = [
    "support", "helpdesk", "customer", "service", "update", "upgrade",
    "security", "secure", "safety", "protection"
]
ACCOUNT_KEYWORDS = [
    "account", "myaccount", "profile", "password", "credential",
    "ssn", "social"
]
ALL_PHISHING_KEYWORDS = (
    FINANCIAL_KEYWORDS + ACTION_KEYWORDS + URGENCY_KEYWORDS +
    REWARD_KEYWORDS + SUPPORT_KEYWORDS + ACCOUNT_KEYWORDS
)

# ══════════════════════════════════════════════════════════════
#  SECTION 4B — KNOWN BRANDS (for impersonation check)
# ══════════════════════════════════════════════════════════════
KNOWN_BRANDS = [
    "paypal", "ebay", "amazon", "apple", "microsoft", "google",
    "facebook", "instagram", "twitter", "netflix", "spotify", "steam",
    "discord", "linkedin", "dropbox", "adobe", "chase", "citibank",
    "wellsfargo", "bankofamerica", "irs", "fedex", "ups", "dhl"
]

# ══════════════════════════════════════════════════════════════
#  SECTION 3B — TYPOSQUATTING SUBSTITUTION PATTERNS
# ══════════════════════════════════════════════════════════════
TYPOSQUATTING_PATTERNS = [
    "paypa1", "g00gle", "amaz0n", "faceb00k", "micros0ft",
    "app1e", "tw1tter", "1nstagram"
]

# ══════════════════════════════════════════════════════════════
#  SECTION 6 — SEVERITY WEIGHTS
#  CRITICAL = 3pts  HIGH = 2pts  MEDIUM = 1pt
# ══════════════════════════════════════════════════════════════
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"


def get_verdict(score: int) -> str:
    """Map total score to a text verdict."""
    if score == 0:
        return "safe"
    elif score <= 2:
        return "low_risk"
    elif score <= 4:
        return "suspicious"
    else:
        return "phishing"


# ──────────────────────────────────────────────────────────────
#  HELPER: Extract registered domain (last 2 labels before TLD
#  is approximated as last 2 dot-segments of hostname)
# ──────────────────────────────────────────────────────────────
def get_registered_domain(hostname: str) -> str:
    """Return 'domain.tld' portion from full hostname."""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def get_tld(hostname: str) -> str:
    """Return the TLD (last label) from a hostname."""
    parts = hostname.split(".")
    return parts[-1] if parts else ""


# ══════════════════════════════════════════════════════════════
#  SECTION 1 — ADVANCED INPUT VALIDATION
# ══════════════════════════════════════════════════════════════
def is_valid_url(url: str) -> tuple[bool, str]:
    """
    Validates the URL structurally before any phishing analysis.
    Returns (True, "") if valid, or (False, reason) if invalid.
    """
    url = url.strip()

    # Empty / whitespace only
    if not url:
        return False, "Please enter a proper and complete URL"

    # Must not contain spaces
    if " " in url:
        return False, "Please enter a proper and complete URL"

    # Quick reject: just a file-system path or email address
    if url.startswith("/") or url.startswith("\\"):
        return False, "Please enter a proper and complete URL"
    if re.match(r"^[^@\s]+@[^@\s]+$", url) and "://" not in url:
        return False, "Please enter a proper and complete URL"

    # Dangerous/special protocols that are still "valid" strings —
    # pass through to phishing engine for CRITICAL flagging, don't reject
    dangerous_protos = ("javascript://", "vbscript://", "data:")
    if any(url.lower().startswith(p) for p in dangerous_protos):
        return True, ""  # valid input — will get CRITICAL flags

    # Must have a recognisable protocol; bare words without :// rejected
    if "://" not in url:
        # Allow if it at least looks like a domain (has a dot, no gap)
        if "." not in url or url.startswith(".") or url.endswith("."):
            return False, "Please enter a proper and complete URL"
        # It's a bare domain — pass through for protocol-missing flag
        hostname_bare = url.split("/")[0]
        tld_bare = hostname_bare.rsplit(".", 1)[-1]
        if not tld_bare or len(tld_bare) < 2:
            return False, "Please enter a proper and complete URL"
        return True, ""

    proto, rest = url.split("://", 1)
    proto = proto.lower()

    # Only recognise known protocols; reject malformed ones
    known_protos = {"http", "https", "ftp", "ws", "wss",
                    "file", "data", "javascript", "vbscript"}
    if proto not in known_protos:
        return False, "Please enter a proper and complete URL"

    # For http/https/ftp — need a real host after the ://
    if proto in ("http", "https", "ftp", "ws", "wss", "file"):
        domain_part = rest.split("/")[0].split("?")[0].split("#")[0]

        # Bare protocol with nothing (http://)
        if not domain_part or domain_part.strip() == "":
            return False, "Please enter a proper and complete URL"

        # Remove port
        hostname = domain_part.split(":")[0].lower()

        # Localhost / internal addresses — reject
        blocked_hosts = {
            "localhost", "127.0.0.1", "0.0.0.0", "::1"
        }
        if hostname in blocked_hosts:
            return False, "Please enter a proper and complete URL"

        # IPv6 literal — allow (will be flagged by phishing engine)
        if hostname.startswith("["):
            return True, ""

        # Must have at least one dot
        if "." not in hostname:
            return False, "Please enter a proper and complete URL"

        # Must not start with a dot: http://.com
        if hostname.startswith("."):
            return False, "Please enter a proper and complete URL"

        # Each label must be non-empty (no consecutive dots)
        labels = hostname.split(".")
        if any(l == "" for l in labels):
            return False, "Please enter a proper and complete URL"

        # TLD must have ≥ 2 chars
        tld = labels[-1]
        if len(tld) < 2:
            return False, "Please enter a proper and complete URL"

        # Reject clearly invalid IPs (all octets > 255)
        ip_match = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$", hostname)
        if ip_match:
            octets = [int(g) for g in ip_match.groups()]
            if any(o > 255 for o in octets):
                return False, "Please enter a proper and complete URL"

        # Domain labels too short (e.g. a.b or x.y)
        if all(len(l) <= 2 for l in labels[:-1]) and len(labels) == 2:
            return False, "Please enter a proper and complete URL"

        # Non-ASCII in domain — allow (punycode handled by engine)
        # (Punycode xn-- is valid ASCII and passes fine)

    return True, ""


# ══════════════════════════════════════════════════════════════
#  SECTION 2/3/4/5/6 — MAIN ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════
def analyze_url(url: str) -> dict:
    """
    Runs all phishing detection rules against a pre-validated URL.
    Returns a dict with verdict, score, flags, pass_count, fail_count.
    Each flag: {"severity": CRITICAL|HIGH|MEDIUM, "reason": str}
    """
    url_lower = url.lower()
    flags = []      # list of {"severity":..., "reason":...}
    score = 0
    checks_passed = 0
    checks_failed = 0

    def flag(severity: str, reason: str):
        nonlocal score, checks_failed
        weights = {CRITICAL: 3, HIGH: 2, MEDIUM: 1}
        score += weights.get(severity, 1)
        flags.append({"severity": severity, "reason": reason})
        checks_failed += 1

    def passed(reason: str):
        nonlocal checks_passed
        checks_passed += 1

    # ── Parse URL ─────────────────────────────────────────────
    try:
        parsed = urlparse(url_lower if "://" in url_lower else "https://" + url_lower)
    except Exception:
        parsed = urlparse("")
    hostname  = parsed.hostname or ""
    scheme    = parsed.scheme or ""
    path      = parsed.path or ""
    query_str = parsed.query or ""
    fragment  = parsed.fragment or ""

    # Remove port from hostname if present
    hostname = hostname.split(":")[0] if ":" in hostname else hostname
    registered_domain = get_registered_domain(hostname)
    tld = get_tld(hostname)

    # ── SECTION 7: Whitelist (https only) ─────────────────────
    is_whitelisted = (
        registered_domain in WHITELIST_DOMAINS
        and url_lower.startswith("https://")
    )
    # Whitelisted HTTPS domains skip keyword + brand impersonation checks
    # BUT still run protocol + structural checks

    # ══ SECTION 2 — Protocol Checks ═══════════════════════════

    # Rule 2a — Dangerous protocols: CRITICAL
    dangerous_protos = ("javascript", "vbscript", "data")
    if scheme in dangerous_protos or url_lower.startswith("javascript:") or url_lower.startswith("data:"):
        flag(CRITICAL, "Extremely dangerous protocol detected — possible script injection attack")
    # Rule 2b — FTP
    elif scheme == "ftp":
        flag(HIGH, "Uses FTP protocol — insecure and uncommon for legitimate websites")
    # Rule 2c — WebSocket
    elif scheme in ("ws", "wss"):
        flag(HIGH, "Unusual WebSocket protocol detected")
    # Rule 2d — File
    elif scheme == "file":
        flag(HIGH, "Local file protocol detected — not a web URL")
    # Rule 2e — Plain HTTP
    elif url_lower.startswith("http://"):
        flag(HIGH, "Uses insecure HTTP protocol — data is transmitted unencrypted")
        passed("Protocol check")
    # Rule 2f — No / missing protocol
    elif not url_lower.startswith("https://"):
        flag(HIGH, "Missing or invalid protocol — cannot verify connection security")
    else:
        # https:// — PASS
        passed("Secure HTTPS protocol confirmed")

    # Skip remaining checks for dangerous protocol injections (no domain to parse)
    if scheme in ("javascript", "vbscript", "data") or url_lower.startswith("javascript:") or url_lower.startswith("data:"):
        verdict = get_verdict(score)
        return _build_response(verdict, score, flags, checks_passed, checks_failed)

    # ══ SECTION 3A — IP Address Usage ═════════════════════════
    ip4_match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", hostname)
    if ip4_match:
        octets = [int(g) for g in ip4_match.groups()]
        # Private/reserved ranges
        is_private = (
            octets[0] == 10 or
            (octets[0] == 172 and 16 <= octets[1] <= 31) or
            (octets[0] == 192 and octets[1] == 168) or
            octets[0] == 127
        )
        if is_private:
            flag(CRITICAL, "Uses private/internal IP address — highly suspicious")
        else:
            flag(CRITICAL, "Uses raw IPv4 address instead of a domain name — common phishing tactic")
    elif hostname.startswith("[") or hostname == "::1":
        # IPv6
        flag(HIGH, "Uses IPv6 address — unusual for legitimate websites")
    else:
        passed("Domain name (not raw IP address)")

    # ══ SECTION 3B — Domain Heuristics ═══════════════════════

    # Rule 3B-1: Typosquatting (number substitution)
    typo_found = [p for p in TYPOSQUATTING_PATTERNS if p in url_lower]
    if typo_found:
        flag(HIGH, f"Numeric character substitution detected — typosquatting attack: {', '.join(typo_found)}")
    else:
        passed("No typosquatting patterns detected")

    # Rule 3B-2: Randomly generated domain heuristic
    domain_label = registered_domain.split(".")[0]  # the SLD
    if not is_whitelisted:
        if re.match(r"^[a-z0-9]{6,}$", domain_label) and re.search(r"\d", domain_label) and re.search(r"[a-z]", domain_label):
            flag(MEDIUM, "Domain name appears randomly generated — common in phishing campaigns")

    # Rule 3B-3: Very short domain (SLD < 4 chars)
    if len(domain_label) < 4 and not ip4_match:
        flag(MEDIUM, "Suspiciously short domain name")
    else:
        if not typo_found:
            passed("Domain name length is normal")

    # ══ SECTION 3C — TLD Risk ═════════════════════════════════
    if tld in HIGH_RISK_TLDS:
        flag(HIGH, f"High-risk or free TLD detected (.{tld}) — commonly used in phishing campaigns")
    elif tld in WATCHLIST_TLDS:
        flag(MEDIUM, f"Uncommon TLD (.{tld}) — verify this domain is legitimate")
    else:
        passed(f"TLD (.{tld}) is not high-risk")

    # ══ SECTION 3D — Subdomain Abuse ══════════════════════════
    # Rule 3D-1: Too many subdomains (> 3 dots in full hostname)
    dot_count = hostname.count(".")
    if dot_count > 3:
        flag(HIGH, "Excessive subdomains detected — possible domain spoofing")
    else:
        passed(f"Normal subdomain structure ({dot_count} dot(s))")

    # Rule 3D-2: Known brand appearing as subdomain (not as reg domain)
    if not is_whitelisted:
        subdomains = hostname[: -(len(registered_domain) + 1)] if hostname.endswith(registered_domain) else ""
        for brand in KNOWN_BRANDS:
            if brand in subdomains:
                flag(CRITICAL, f"Known brand name '{brand}' used as subdomain — classic spoofing technique (actual domain: {registered_domain})")
                break

    # ══ SECTION 4A — Phishing keywords ═══════════════════════
    if not is_whitelisted:
        found_kw = [kw for kw in ALL_PHISHING_KEYWORDS if kw in url_lower]
        if found_kw:
            flag(MEDIUM, f"Contains suspicious phishing keyword(s): {', '.join(found_kw)}")
        else:
            passed("No suspicious keywords found")
    else:
        passed("Whitelisted domain — keyword checks skipped")

    # ══ SECTION 4B — Brand Impersonation ═════════════════════
    if not is_whitelisted:
        for brand in KNOWN_BRANDS:
            if brand in url_lower and brand not in registered_domain:
                flag(CRITICAL, f"Impersonates known brand '{brand}' — brand appears in URL but not as registered domain (actual: {registered_domain})")
                break
        else:
            passed("No brand impersonation detected")

    # ══ SECTION 5A — URL Length ══════════════════════════════
    url_len = len(url)
    if url_len > 100:
        flag(HIGH, f"URL is extremely long ({url_len} chars) — strong indicator of phishing")
    elif url_len > 75:
        flag(MEDIUM, f"URL is unusually long ({url_len} chars) — often used to hide malicious destination")
    else:
        passed(f"URL length is within safe limits ({url_len} characters)")

    # ══ SECTION 5B — Special Character Abuse ═════════════════

    # Rule 5B-1: @ symbol — CRITICAL
    if "@" in url:
        flag(CRITICAL, "Contains @ symbol — browser ignores everything before @ and redirects to destination after it")
    else:
        passed("No @ symbol detected")

    # Rule 5B-2: Multiple // after initial protocol
    url_after_proto = url.split("://", 1)[-1] if "://" in url else url
    if "//" in url_after_proto:
        flag(MEDIUM, "Multiple slashes detected — possible redirect obfuscation")
    else:
        passed("No double-slash obfuscation detected")

    # Rule 5B-3: Hyphenated brand name
    for brand in KNOWN_BRANDS:
        if re.search(rf"{brand}-\w+", url_lower) or re.search(rf"\w+-{brand}", url_lower):
            flag(HIGH, f"Hyphenated brand name detected ({brand}-...) — common phishing domain pattern")
            break
    else:
        passed("No hyphenated brand name detected")

    # Rule 5B-4: Percent-encoded characters
    if re.search(r"%[0-9a-fA-F]{2}", url):
        flag(MEDIUM, "URL encoding detected (%XX) — possible obfuscation attempt")
    else:
        passed("No suspicious URL encoding detected")

    # Rule 5B-5: Punycode / homograph attack
    if "xn--" in url_lower:
        flag(HIGH, "Punycode/internationalized domain detected (xn--) — possible homograph attack")
    else:
        passed("No Punycode obfuscation detected")

    # Rule 5B-6: Consecutive dots
    if ".." in hostname:
        flag(HIGH, "Malformed domain with consecutive dots detected")
    else:
        passed("No consecutive dots in domain")

    # Rule 5B-7: Tilde in path
    if "~" in path:
        flag(MEDIUM, "Tilde character (~) in path — sometimes used in phishing URLs")
    else:
        passed("No tilde character in path")

    # ══ SECTION 5C — Path & Query String Analysis ═════════════

    # Rule 5C-1: Sensitive words in PATH (not just anywhere in URL)
    path_kw = ["login", "signin", "verify", "account", "password", "reset"]
    found_path_kw = [kw for kw in path_kw if kw in path.lower()]
    if found_path_kw:
        flag(MEDIUM, f"Suspicious path segment(s) detected: {', '.join(found_path_kw)}")
    else:
        passed("No suspicious path segments")

    # Rule 5C-2: Open redirect parameters
    open_redirect_params = ["redirect", "url", "next", "return", "goto", "redir"]
    if query_str:
        qs = parse_qs(query_str)
        found_redirects = [p for p in open_redirect_params if p in qs]
        if found_redirects:
            flag(HIGH, f"Open redirect parameter(s) detected: {', '.join(found_redirects)} — URL may redirect to a malicious site")
        else:
            passed("No open redirect parameters detected")

        # Rule 5C-3: Suspicious auth tokens
        auth_params = ["token", "session", "auth", "key"]
        for param in auth_params:
            if param in qs:
                val = qs[param][0] if qs[param] else ""
                if len(val) > 20:  # Long random-looking string
                    flag(MEDIUM, f"Suspicious authentication token in URL parameter '{param}'")
                    break
        else:
            passed("No suspicious auth tokens in query string")

        # Rule 5C-4: Excessive query parameters
        num_params = len(qs)
        if num_params > 3:
            flag(MEDIUM, f"Excessive query parameters ({num_params}) — unusual for legitimate pages")
        else:
            passed(f"Normal number of query parameters ({num_params})")
    else:
        passed("No query string (clean URL)")

    # Rule 5C-5: Suspicious fragment
    if fragment and any(kw in fragment for kw in ["login", "redirect", "signin"]):
        flag(MEDIUM, "Suspicious fragment identifier detected")
    else:
        passed("No suspicious URL fragment")

    # ── Build & return response ────────────────────────────────
    verdict = get_verdict(score)

    # Whitelist override: force SAFE if whitelisted and no critical flags
    if is_whitelisted and not any(f["severity"] == CRITICAL for f in flags):
        verdict = "safe"
        score = max(score - 2, 0)  # Reduce score for established trusted domain

    return _build_response(verdict, score, flags, checks_passed, checks_failed)


def _build_response(verdict, score, flags, checks_passed, checks_failed):
    """Assembles the final JSON response dict."""
    verdicts = {
        "safe":       "This URL passed all security checks. Safe to visit.",
        "low_risk":   "This URL has minor suspicious traits — proceed with caution.",
        "suspicious": "This URL is suspicious — we recommend NOT visiting it.",
        "phishing":   "High confidence phishing URL — do NOT visit this link."
    }
    return {
        "result":        verdict,
        "score":         score,
        "verdict_label": verdicts.get(verdict, ""),
        "flags":         flags,           # list of {severity, reason}
        "checks_passed": checks_passed,
        "checks_failed": checks_failed
    }


# ══════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data["url"].strip()

    # Section 1 — Validate before any analysis
    valid, err_msg = is_valid_url(url)
    if not valid:
        return jsonify({
            "result":  "invalid",
            "message": err_msg or "Please enter a proper and complete URL"
        }), 200

    analysis = analyze_url(url)
    return jsonify(analysis)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
