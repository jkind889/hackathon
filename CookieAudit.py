from __future__ import annotations

import re
import importlib
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

TRACKER_PATTERNS = {
    "analytics": [r"_ga", r"_gid", r"_gat", r"analytics", r"mixpanel", r"amplitude", r"segment"],
    "advertising": [r"_fbp", r"doubleclick", r"ad[sx]?", r"ttclid", r"gcl_au", r"criteo"],
    "session": [r"session", r"sess", r"csrf", r"auth", r"token"],
    "functional": [r"pref", r"lang", r"theme", r"remember"],
}

DISCLOSURE_TERMS = {
    "analytics": ["analytics", "measurement", "google analytics", "mixpanel", "amplitude", "segment"],
    "advertising": ["advertising", "ad network", "targeted ads", "remarketing", "doubleclick", "facebook pixel"],
    "session": ["strictly necessary", "essential cookies", "authentication", "session cookies"],
    "functional": ["preferences", "functional cookies", "site settings", "language settings"],
}


CONSENT_BUTTON_PATTERNS = {
    "after_accept": [
        r"accept",
        r"allow",
        r"agree",
        r"ok",
        r"i\s*agree",
    ],
    "after_reject": [
        r"reject",
        r"decline",
        r"deny",
        r"refuse",
        r"necessary\s*only",
    ],
}


ARCHIVE_REPOS = [
    "OpenTermsArchive/pga-versions",
    "citp/privacy-policy-historical",
]


def _normalize_url(site_url: str) -> str:
    url = site_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _domain_key(site_url: str) -> str:
    netloc = urlparse(site_url).netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc


def _fetch_html(url: str, timeout: int = 20) -> str:
    response = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": "Mozilla/5.0 (Privacy-Audit-Bot)"},
    )
    response.raise_for_status()
    return response.text


def _extract_text_from_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for node in soup(["script", "style", "noscript"]):
        node.decompose()
    text = soup.get_text("\n")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines)


def _find_policy_links(base_url: str, html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    keywords = ("privacy", "policy", "terms", "tos")

    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href", "")
        anchor_text = (anchor.get_text(" ") or "").lower()
        href_lower = href.lower()
        if any(key in href_lower for key in keywords) or any(key in anchor_text for key in keywords):
            links.append(urljoin(base_url, href))

    deduped: list[str] = []
    seen = set()
    for link in links:
        if link not in seen:
            deduped.append(link)
            seen.add(link)
    return deduped


def _github_tree_paths(repo: str) -> list[str]:
    for branch in ("main", "master"):
        api_url = f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
        response = requests.get(api_url, timeout=25)
        if response.status_code == 200:
            data = response.json()
            return [item.get("path", "") for item in data.get("tree", []) if item.get("type") == "blob"]
    return []


def _github_raw_url(repo: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/main/{path}"


def _fetch_policy_from_archive(site_url: str) -> dict[str, Any]:
    domain = _domain_key(site_url)
    domain_tokens = [domain, domain.replace(".", "-"), domain.split(".")[0]]
    policy_tokens = ("privacy", "policy", "terms", "tos")

    for repo in ARCHIVE_REPOS:
        try:
            paths = _github_tree_paths(repo)
        except Exception:
            continue

        matched_paths = []
        for path in paths:
            lower_path = path.lower()
            if any(token in lower_path for token in domain_tokens) and any(token in lower_path for token in policy_tokens):
                matched_paths.append(path)

        for path in matched_paths[:3]:
            raw_url = _github_raw_url(repo, path)
            try:
                response = requests.get(raw_url, timeout=20)
                if response.status_code != 200:
                    continue
                text = response.text.strip()
                if len(text) < 200:
                    continue
                return {
                    "ok": True,
                    "text": text,
                    "source_url": raw_url,
                    "source_label": f"Archive ({repo})",
                }
            except Exception:
                continue

    return {
        "ok": False,
        "text": "",
        "source_url": "",
        "source_label": "",
    }


def fetch_policy_text_for_site(site_url: str) -> dict[str, Any]:
    target_url = _normalize_url(site_url)

    try:
        homepage_html = _fetch_html(target_url)
        candidate_links = _find_policy_links(target_url, homepage_html)

        for link in candidate_links[:8]:
            try:
                html = _fetch_html(link)
                text = _extract_text_from_html(html)
                if len(text) >= 400:
                    return {
                        "ok": True,
                        "text": text,
                        "source_url": link,
                        "source_label": "Site policy page",
                    }
            except Exception:
                continue
    except Exception:
        pass

    archive_result = _fetch_policy_from_archive(target_url)
    if archive_result.get("ok"):
        return archive_result

    return {
        "ok": False,
        "text": "",
        "source_url": "",
        "source_label": "",
        "error": "Could not auto-find policy/TOS on the site or the configured archives.",
    }


def auto_collect_cookies(site_url: str, consent_state: str) -> dict[str, Any]:
    try:
        playwright_sync_api = importlib.import_module("playwright.sync_api")
        sync_playwright = getattr(playwright_sync_api, "sync_playwright")
    except Exception:
        return {
            "ok": False,
            "error": "Playwright is not installed. Run: pip install playwright && playwright install chromium",
            "cookie_names": [],
        }

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(site_url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(2000)

            clicked = None
            if consent_state in {"after_accept", "after_reject"}:
                patterns = CONSENT_BUTTON_PATTERNS[consent_state]
                for pattern in patterns:
                    button = page.get_by_role("button", name=re.compile(pattern, re.IGNORECASE)).first
                    if button.is_visible(timeout=1000):
                        button.click(timeout=2000)
                        clicked = pattern
                        page.wait_for_timeout(1500)
                        break

            cookies = context.cookies()
            browser.close()

            cookie_names = sorted({cookie.get("name", "") for cookie in cookies if cookie.get("name")}, key=str.lower)
            return {
                "ok": True,
                "error": None,
                "cookie_names": cookie_names,
                "clicked_pattern": clicked,
                "count": len(cookie_names),
            }
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Auto collection failed: {exc}",
            "cookie_names": [],
        }


def parse_observed_cookies(raw_text: str) -> list[str]:
    if not raw_text:
        return []

    tokens = [part.strip() for part in re.split(r"[\n,;]+", raw_text) if part.strip()]
    names: list[str] = []

    for token in tokens:
        if "=" in token:
            token = token.split("=", 1)[0].strip()
        if token:
            names.append(token)

    return sorted(set(names), key=str.lower)


def classify_cookie(cookie_name: str) -> str:
    lower = cookie_name.lower()
    for category, patterns in TRACKER_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, lower):
                return category
    return "unknown"


def _policy_disclosures(policy_text: str) -> dict[str, bool]:
    text = policy_text.lower()
    disclosed: dict[str, bool] = {}
    for category, terms in DISCLOSURE_TERMS.items():
        disclosed[category] = any(term in text for term in terms)
    return disclosed


def grade_cookie_truthfulness(
    policy_text: str,
    observed_cookie_text: str,
    consent_state: str,
) -> dict[str, Any]:
    cookie_names = parse_observed_cookies(observed_cookie_text)
    classifications = [
        {"name": name, "category": classify_cookie(name)}
        for name in cookie_names
    ]

    category_counts = {"analytics": 0, "advertising": 0, "session": 0, "functional": 0, "unknown": 0}
    for item in classifications:
        category_counts[item["category"]] += 1

    disclosed = _policy_disclosures(policy_text)

    issues: list[dict[str, str]] = []
    score = 100

    non_essential_count = category_counts["analytics"] + category_counts["advertising"]

    if consent_state in {"before_consent", "after_reject"} and non_essential_count > 0:
        score -= min(45, non_essential_count * 12)
        issues.append(
            {
                "severity": "high",
                "title": "Non-essential cookies loaded before consent",
                "detail": "Analytics/advertising cookies were observed when they should usually be blocked.",
            }
        )

    if category_counts["analytics"] > 0 and not disclosed.get("analytics", False):
        score -= 20
        issues.append(
            {
                "severity": "high",
                "title": "Undisclosed analytics tracking",
                "detail": "Analytics-like cookies were observed but analytics disclosure language is weak or missing.",
            }
        )

    if category_counts["advertising"] > 0 and not disclosed.get("advertising", False):
        score -= 25
        issues.append(
            {
                "severity": "high",
                "title": "Undisclosed advertising tracking",
                "detail": "Ad/remarketing-like cookies were observed but advertising disclosure language is weak or missing.",
            }
        )

    if category_counts["unknown"] > 3:
        score -= 10
        issues.append(
            {
                "severity": "medium",
                "title": "Many unknown cookies",
                "detail": "Several cookies could not be classified; manually verify vendor and purpose.",
            }
        )

    if "opt-out" not in policy_text.lower() and "do not sell" not in policy_text.lower():
        score -= 8
        issues.append(
            {
                "severity": "medium",
                "title": "Weak opt-out language",
                "detail": "Policy text does not clearly mention opt-out or Do Not Sell controls.",
            }
        )

    score = max(0, min(100, score))

    if score >= 85:
        grade = "A"
        risk_level = "Low"
    elif score >= 70:
        grade = "B"
        risk_level = "Low"
    elif score >= 55:
        grade = "C"
        risk_level = "Medium"
    elif score >= 40:
        grade = "D"
        risk_level = "High"
    else:
        grade = "F"
        risk_level = "High"

    issues.sort(key=lambda item: {"high": 0, "medium": 1, "low": 2}.get(item["severity"], 3))

    return {
        "score": score,
        "grade": grade,
        "risk_level": risk_level,
        "issues": issues,
        "cookies": classifications,
        "category_counts": category_counts,
        "consent_state": consent_state,
    }
