import asyncio
import ipaddress
import re
import socket
from urllib.parse import parse_qs, unquote, urlparse

import cloudscraper
import httpx
import tldextract

URL_RE = re.compile(
    r"((?:https?://)?(?:[\w-]+\.)+[\w-]{2,}(?::\d+)?(?:/[^\s<>\"]*)?)",
    re.IGNORECASE,
)

SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly",
    "rebrand.ly", "ow.ly", "shorturl.at", "soo.gd", "trib.al",
    "shorte.st", "buff.ly", "lnkd.in", "rb.gy", "s.id", "clck.ru",
    "bom.to", "bit.do", "v.gd",
}

SAFE_DOMAINS = {
    "kun.uz",
    "www.kun.uz",
    "mediapark.uz",
    "www.mediapark.uz",
    "google.com",
    "youtube.com",
    "telegram.org",
    "wikipedia.org",
    "olx.uz",
}

KNOWN_BAD_DOMAINS = {
    "vertezworks.com",
    "www.vertezworks.com",
    "web-mail.free.fr.s-host.net",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "cam", "lol",
    "icu", "work", "party", "gq", "tk", "ml", "cf", "support",
    "shop", "buzz", "quest", "rest", "fit", "cyou", "sbs",
    "hair", "monster", "live",
}

PHISH_WORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "update", "unlock", "bonus", "free", "airdrop", "wallet", "claim",
    "password", "support", "restore", "authorize", "confirm", "billing",
    "invoice", "bank", "card", "otp", "2fa", "crypto", "gift", "reward",
    "webmail", "mailbox", "account", "suspend", "blocked", "limited",
    "prize", "winner", "giveaway", "connect", "metamask", "seed",
    "recovery",
]

SENSITIVE_INPUT_WORDS = [
    "password", "passwd", "otp", "verification", "card", "cvv",
    "pin", "seed", "recovery", "private key", "mnemonic",
]


def extract_urls(text: str) -> list[str]:
    text = text or ""
    urls = []

    for match in URL_RE.findall(text):
        url = match.strip().rstrip(".,;:!?)\\]}'\"")

        if not url:
            continue

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        urls.append(url)

    return list(dict.fromkeys(urls))


def normalize_to_url(text: str) -> str | None:
    text = (text or "").strip()

    if not text:
        return None

    found = extract_urls(text)

    if found:
        return found[0]

    if "." in text and " " not in text:
        if not text.startswith(("http://", "https://")):
            return "https://" + text
        return text

    return None


async def dns_resolves(host: str) -> bool:
    if not host:
        return False

    loop = asyncio.get_running_loop()

    def _resolve():
        socket.gethostbyname(host)

    try:
        await loop.run_in_executor(None, _resolve)
        return True
    except Exception:
        return False


def domain_parts(host: str):
    ext = tldextract.extract(host or "")
    domain = (ext.domain or "").lower()
    suffix = (ext.suffix or "").lower()
    registered_domain = f"{domain}.{suffix}" if domain and suffix else host
    return ext, domain, suffix, registered_domain


def is_known_bad(host: str) -> bool:
    host = (host or "").lower().strip()
    return host in KNOWN_BAD_DOMAINS or any(
        host.endswith("." + d)
        for d in KNOWN_BAD_DOMAINS
    )


def is_safe_domain(host: str) -> bool:
    host = (host or "").lower().strip()
    return host in SAFE_DOMAINS or any(
        host.endswith("." + d)
        for d in SAFE_DOMAINS
    )


def suspicious_random_domain(domain: str) -> bool:
    if not domain or len(domain) < 11:
        return False

    digits = sum(ch.isdigit() for ch in domain)
    vowels = sum(ch in "aeiou" for ch in domain.lower())
    hyphens = domain.count("-")

    return digits >= 4 or vowels <= 2 or hyphens >= 2


async def expand_url(url: str):
    reasons = []
    redirected = False
    status_code = None
    final_url = url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if host in SHORTENER_DOMAINS:
        reasons.append("Short link aniqlandi")

    try:
        scraper = cloudscraper.create_scraper(
            browser={
                "browser": "chrome",
                "platform": "windows",
                "mobile": False,
            }
        )

        resp = scraper.get(
            url,
            allow_redirects=True,
            timeout=15,
        )

        status_code = resp.status_code
        final_url = resp.url

        if final_url.rstrip("/") != url.rstrip("/"):
            redirected = True
            reasons.append("Redirect mavjud")

        if status_code >= 400:
            reasons.append(f"Server xatosi qaytardi: HTTP {status_code}")

        return final_url, reasons, redirected, status_code

    except Exception:
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=httpx.Timeout(12.0, connect=8.0),
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/136.0.0.0 Safari/537.36"
                    ),
                },
            ) as client:

                resp = await client.get(url)

                status_code = resp.status_code
                final_url = str(resp.url)

                if final_url.rstrip("/") != url.rstrip("/"):
                    redirected = True
                    reasons.append("Redirect mavjud")

                if status_code >= 400:
                    reasons.append(f"Server xatosi qaytardi: HTTP {status_code}")

                return final_url, reasons, redirected, status_code

        except Exception:
            if host in SHORTENER_DOMAINS:
                reasons.append("Short link ochib bo‘lmadi")
            else:
                reasons.append("Saytga ulanishda muammo bor")

            return url, reasons, False, None


async def fetch_page(url: str):
    try:
        scraper = cloudscraper.create_scraper(
            browser={
                "browser": "chrome",
                "platform": "windows",
                "mobile": False,
            }
        )

        resp = scraper.get(url, timeout=15)

        ctype = (resp.headers.get("content-type") or "").lower()
        text = ""

        if "text/html" in ctype or "text/plain" in ctype or not ctype:
            text = resp.text[:120000]

        return text, resp.status_code

    except Exception:
        return "", None


async def analyze_url(text: str):
    raw_url = normalize_to_url(text)

    if not raw_url:
        return {
            "input_url": (text or "").strip(),
            "final_url": (text or "").strip(),
            "risk_score": 95,
            "verdict": "danger",
            "reasons": ["URL topilmadi yoki format noto‘g‘ri"],
        }

    final_url, expand_reasons, redirected, expand_status = await expand_url(raw_url)

    parsed = urlparse(final_url)
    host = (parsed.hostname or "").lower()
    full_url = unquote(final_url.lower())
    path_qs = unquote(f"{parsed.path or ''}?{parsed.query or ''}".lower())

    if is_known_bad(host):
        return {
            "input_url": raw_url,
            "final_url": final_url,
            "risk_score": 95,
            "verdict": "danger",
            "reasons": ["Bu domen lokal qora ro‘yxatda zararli deb belgilangan"],
        }

    if is_safe_domain(host):
        return {
            "input_url": raw_url,
            "final_url": final_url,
            "risk_score": 5,
            "verdict": "safe",
            "reasons": ["Ishonchli domen ro‘yxatida mavjud"],
        }

    reasons = []
    risk = 0

    def add(points: int, reason: str):
        nonlocal risk
        risk += points

        if reason not in reasons:
            reasons.append(reason)

    ext, domain, suffix, registered_domain = domain_parts(host)

    tld = (suffix or "").split(".")[-1].lower()

    is_short = host in SHORTENER_DOMAINS

    for r in expand_reasons:
        if r not in reasons:
            reasons.append(r)

    if is_short:
        add(20, "Short link")

    if redirected:
        add(15, "Redirect mavjud")

    if expand_status and expand_status >= 400:
        add(10, f"Server xatosi: HTTP {expand_status}")

    if is_short and expand_status and expand_status >= 400:
        add(15, "Short link server tomonidan bloklandi")

    if parsed.scheme != "https":
        add(15, "HTTPS ishlatilmagan")

    dns_ok = True

    if host:
        dns_ok = await dns_resolves(host)

    if host and not dns_ok:
        add(70, "DNS resolve bo‘lmadi yoki domen yashirilgan")

    try:
        ipaddress.ip_address(host)
        add(35, "Domen o‘rniga IP ishlatilgan")
    except Exception:
        pass

    if "xn--" in host:
        add(25, "Punycode domen")

    if tld in SUSPICIOUS_TLDS:
        add(25, f"Shubhali TLD: .{tld}")

    if suspicious_random_domain(domain):
        add(16, "Tasodifiy domen")

    if len(final_url) > 120:
        add(10, "URL juda uzun")

    if host.count(".") >= 4:
        add(16, "Subdomain juda ko‘p")

    if "@" in final_url:
        add(30, "URL ichida @ belgisi bor")

    if any(k in path_qs for k in [
        "redirect=", "url=", "next=", "target="
    ]):
        add(18, "Redirect parametrlari bor")

    url_hits = [w for w in PHISH_WORDS if w in full_url]

    if len(url_hits) >= 3:
        add(25, "URL ichida phishing so‘zlari bor")

    qs = parse_qs(parsed.query)

    if len(qs) >= 6:
        add(12, "Query param juda ko‘p")

    page_text, page_status = await fetch_page(final_url)

    if page_status and page_status >= 400:
        add(10, f"Sahifa HTTP {page_status}")

    if page_text:
        lower_page = page_text.lower()

        page_hits = [w for w in PHISH_WORDS if w in lower_page]

        if len(page_hits) >= 6:
            add(20, "Phishingga o‘xshash matn")

        has_form = "<form" in lower_page

        has_password_input = (
            'type="password"' in lower_page
            or "type='password'" in lower_page
        )

        sensitive_count = sum(
            1 for w in SENSITIVE_INPUT_WORDS
            if w in lower_page
        )

        if has_form and has_password_input and sensitive_count >= 2:
            add(45, "Parol formasi mavjud")

        elif (
            has_form
            and sensitive_count >= 4
            and any(x in lower_page for x in [
                "verify", "otp", "login",
                "wallet", "bank", "confirm"
            ])
        ):
            add(35, "Maxfiy ma’lumot so‘rashi mumkin")

        if (
            "metamask" in lower_page
            or "seed phrase" in lower_page
            or "recovery phrase" in lower_page
        ):
            add(45, "Kripto wallet ma’lumotlari so‘ralmoqda")

    if host and not dns_ok:
        risk = max(risk, 70)

    if is_short and redirected:
        risk = max(risk, 35)

    if is_short and expand_status and expand_status >= 400:
        risk = max(risk, 40)

    risk = max(0, min(100, risk))

    if risk >= 60:
        verdict = "danger"
    elif risk >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    if not reasons:
        reasons.append("Kuchli shubha topilmadi")

    return {
        "input_url": raw_url,
        "final_url": final_url,
        "risk_score": risk,
        "verdict": verdict,
        "reasons": reasons,
    }


def safe_md(text: str) -> str:
    if text is None:
        return ""

    escape_chars = r"_*[]()~`>#+-=|{}.!"
    out = str(text)

    for ch in escape_chars:
        out = out.replace(ch, "\\" + ch)

    return out


def format_result_message(result: dict) -> str:
    risk = int(result["risk_score"])
    safety_score = max(0, 100 - risk)

    if result["verdict"] == "safe":
        status_line = "🟢 *Xavfsizroq*"
        detection = "0 / 10"

    elif result["verdict"] == "suspicious":
        status_line = "🟡 *Shubhali*"
        detection = "5 / 10"

    else:
        status_line = "🔴 *Xavfli*"
        detection = "9 / 10"

    reasons_text = "\n".join(
        f"• {safe_md(r)}"
        for r in result["reasons"]
    )

    return (
        "🔍 *Havola tekshiruvi*\n\n"
        f"🔗 *Link:* `{safe_md(result['input_url'])}`\n"
        f"➡️ *Asl manzil:* `{safe_md(result['final_url'])}`\n\n"
        f"📊 *Xavfsizlik balli:* `{safety_score}/100`\n"
        f"🧪 *Aniqlash darajasi:* `{detection}`\n"
        f"⚠️ *Holat:* {status_line}\n\n"
        f"🧠 *Aniqlangan sabablar:*\n{reasons_text}\n\n"
        "📌 *Tavsiya:*\n"
        "Havola shubhali bo‘lsa uni ochmang, "
        "parol, karta ma'lumoti yoki OTP kiritmang."
    )