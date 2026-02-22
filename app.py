from flask import Flask, render_template, request
from Parser import analyze_policy_text
from CookieAudit import auto_collect_cookies, fetch_policy_text_for_site, grade_cookie_truthfulness
from markupsafe import Markup, escape
import importlib
import json
import os
import re
from urllib.parse import urlparse
from dotenv import load_dotenv

app = Flask(__name__)

MODEL_CANDIDATES = [
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-flash",
]

KNOWN_ENTITY_HINTS = {
    "x.com": "X (formerly Twitter, twitter.com)",
    "twitter.com": "X (formerly Twitter)",
    "meta.com": "Meta (Facebook/Instagram parent)",
    "facebook.com": "Meta (Facebook)",
}


def _candidate_models_from_api(client) -> list[str]:
    discovered: list[str] = []
    try:
        for model in client.models.list():
            name = getattr(model, "name", "")
            if not name or "gemini" not in name.lower():
                continue
            discovered.append(name)
            if name.startswith("models/"):
                discovered.append(name.split("/", 1)[1])
    except Exception:
        return []

    ordered: list[str] = []
    seen = set()
    for name in discovered:
        if name not in seen:
            ordered.append(name)
            seen.add(name)
    return ordered


def _domain_label(site_url: str) -> str:
    netloc = urlparse(site_url).netloc.lower().strip()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc or site_url


def _entity_hint(site_url: str) -> str:
    domain = _domain_label(site_url)
    return KNOWN_ENTITY_HINTS.get(domain, domain)


def _generate_breach_snapshot(site_url: str) -> tuple[str | None, str | None]:
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None, "GEMINI_API_KEY missing, so AI breach lookup is unavailable."

    try:
        genai = importlib.import_module("google.genai")
        client = genai.Client(api_key=api_key)
    except Exception:
        return None, "google-genai dependency is unavailable for breach lookup."

    target = _domain_label(site_url)
    entity = _entity_hint(site_url)
    prompt = (
        "You are assisting with a cybersecurity risk snapshot. "
        f"For the organization or website '{target}' (entity hint: '{entity}'), return STRICT JSON only (no markdown). "
        "Schema: {\"incidents\":[{\"date\":\"\",\"event\":\"\",\"impact\":\"\",\"severity\":\"HIGH|MEDIUM|LOW\",\"source_url\":\"\"}],\"synopsis\":\"\"}. "
        "Use up to 5 prominent publicly reported incidents. "
        "Use known rebrands/aliases where applicable (for example, x.com is X formerly Twitter). "
        "Each incident must include a source_url when possible. "
        "If uncertain or no reliable incidents, return empty incidents and explain uncertainty in synopsis."
    )

    last_error = None
    try:
        discovered_models = _candidate_models_from_api(client)
    except Exception:
        discovered_models = []
    models_to_try = discovered_models if discovered_models else MODEL_CANDIDATES

    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
            )
            text = (getattr(response, "text", "") or "").strip()
            if text:
                return text, None
        except Exception as exc:
            last_error = exc

    return None, f"AI breach lookup failed: {last_error}" if last_error else "AI breach lookup failed."


def _generate_breach_snapshot_legacy(site_url: str) -> tuple[str | None, str | None]:
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None, "GEMINI_API_KEY missing, so AI breach lookup is unavailable."

    try:
        genai = importlib.import_module("google.genai")
        client = genai.Client(api_key=api_key)
    except Exception:
        return None, "google-genai dependency is unavailable for breach lookup."

    target = _domain_label(site_url)
    entity = _entity_hint(site_url)
    prompt = (
        "You are assisting with a cybersecurity risk snapshot. "
        f"For '{target}' (entity hint: '{entity}'), provide 3-5 prominent publicly reported cybersecurity incidents or data breaches. "
        "For each incident include date, what happened, impact, and if possible a source URL in the same line. "
        "Then add one line starting with 'Synopsis:'. "
        "Use known rebrands/aliases where applicable (e.g., x.com is X formerly Twitter). "
        "Do not invent incidents; if uncertain, state uncertainty clearly."
    )

    last_error = None
    try:
        discovered_models = _candidate_models_from_api(client)
    except Exception:
        discovered_models = []
    models_to_try = discovered_models if discovered_models else MODEL_CANDIDATES

    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
            )
            text = (getattr(response, "text", "") or "").strip()
            if text:
                return text, None
        except Exception as exc:
            last_error = exc

    return None, f"AI breach lookup failed: {last_error}" if last_error else "AI breach lookup failed."


def _extract_json_object(text: str) -> str | None:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    return text[start : end + 1]


def _normalize_severity(level: str) -> str:
    normalized = (level or "").strip().lower()
    if normalized in {"high", "critical", "severe"}:
        return "high"
    if normalized in {"medium", "moderate"}:
        return "medium"
    return "low"


def _breach_grade(incidents: list[dict]) -> tuple[str, str]:
    deductions = {"high": 28, "medium": 16, "low": 8}
    score = 100
    for incident in incidents:
        score -= deductions.get(incident.get("severity", "low"), 8)
    score = max(0, score)

    if score >= 85:
        return "A", "Low"
    if score >= 70:
        return "B", "Low"
    if score >= 55:
        return "C", "Medium"
    if score >= 40:
        return "D", "High"
    return "F", "High"


def _parse_breach_snapshot(snapshot_text: str) -> tuple[list[dict], str, list[str], str, str]:
    json_payload = _extract_json_object(snapshot_text)
    parsed = None
    if json_payload:
        try:
            parsed = json.loads(json_payload)
        except Exception:
            parsed = None

    incidents: list[dict] = []
    synopsis = ""

    if isinstance(parsed, dict):
        synopsis = str(parsed.get("synopsis", "")).strip()
        for raw in parsed.get("incidents", [])[:5]:
            if not isinstance(raw, dict):
                continue
            event = str(raw.get("event", "")).strip()
            impact = str(raw.get("impact", "")).strip()
            date = str(raw.get("date", "")).strip()
            source_url = str(raw.get("source_url", "")).strip()
            severity = _normalize_severity(str(raw.get("severity", "")))
            if event:
                incidents.append(
                    {
                        "date": date or "Unknown",
                        "event": event,
                        "impact": impact or "Impact not specified.",
                        "severity": severity,
                        "source_url": source_url if source_url.startswith(("http://", "https://")) else "",
                    }
                )
    else:
        lines = [line.strip() for line in snapshot_text.splitlines() if line.strip()]
        for line in lines:
            if line.startswith("```"):
                continue
            lower = line.lower()
            if lower.startswith("synopsis:"):
                synopsis = line.split(":", 1)[1].strip() if ":" in line else ""
                continue

            cleaned_line = re.sub(r"^[-*•\s]+", "", line).strip()
            if not cleaned_line or cleaned_line in {"{", "}"}:
                continue

            incidents.append(
                {
                    "date": "Unknown",
                    "event": cleaned_line,
                    "impact": "Details not structured by model output.",
                    "severity": "medium",
                    "source_url": "",
                }
            )

            if len(incidents) >= 5:
                break

        if not synopsis:
            synopsis = "Model returned unstructured output; review manually."

    sources = sorted(
        {
            incident["source_url"]
            for incident in incidents
            if incident.get("source_url")
        }
    )

    grade, risk_level = _breach_grade(incidents)
    return incidents, synopsis, sources, grade, risk_level


def _severity_rank(level: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(level, 3)


def _flaw_reason(category_name: str, subgroup_name: str, term: str) -> str:
    if category_name.startswith("5."):
        return "Vague promise with legal wiggle room."
    if category_name.startswith("2."):
        return "Data may leave trusted boundaries."
    if category_name.startswith("1.") and subgroup_name == "High-Risk Identifiers":
        return "Sensitive identifiers enable direct tracking."
    if category_name.startswith("1.") and subgroup_name == "Automated Tracking":
        return "Passive tracking likely without awareness."
    if category_name.startswith("3."):
        return "User control rights may be limited."
    if category_name.startswith("4.") and subgroup_name == "Timelines":
        return "Retention window may be too broad."
    if category_name.startswith("4."):
        return "Security wording is broad, noncommittal."
    return "Potential privacy risk indicator term."


def _extract_flaws(report: dict) -> list[dict]:
    flaws: list[dict] = []
    categories = report.get("categories", {})

    for category_name, category_data in categories.items():
        subgroups = category_data.get("subgroups", {})
        for subgroup_name, hits in subgroups.items():
            for hit in hits:
                term = hit.get("term", "")
                count = hit.get("count", 0)

                severity = "medium"
                if category_name.startswith("5."):
                    severity = "high"
                elif category_name.startswith("2."):
                    severity = "high"
                elif category_name.startswith("1.") and subgroup_name == "High-Risk Identifiers":
                    severity = "high"
                elif category_name.startswith("4.") and subgroup_name == "Timelines":
                    severity = "low"

                flaws.append(
                    {
                        "category": category_name,
                        "subgroup": subgroup_name,
                        "term": term,
                        "count": count,
                        "severity": severity,
                        "reason": _flaw_reason(category_name, subgroup_name, term),
                    }
                )

    flaws.sort(
        key=lambda item: (
            _severity_rank(item["severity"]),
            -item["count"],
            item["term"].lower(),
        )
    )
    return flaws


def _privacy_grade(score: int) -> str:
    if score >= 70:
        return "F"
    if score >= 55:
        return "D"
    if score >= 40:
        return "C"
    if score >= 25:
        return "B"
    return "A"


def _grade_to_points(letter: str) -> float:
    return {
        "A": 4.0,
        "B": 3.0,
        "C": 2.0,
        "D": 1.0,
        "F": 0.0,
    }.get((letter or "").strip().upper(), 0.0)


def _points_to_grade(points: float) -> str:
    if points >= 3.5:
        return "A"
    if points >= 2.5:
        return "B"
    if points >= 1.5:
        return "C"
    if points >= 0.5:
        return "D"
    return "F"


def _grade_to_risk(letter: str) -> str:
    upper = (letter or "").strip().upper()
    if upper in {"A", "B"}:
        return "Low"
    if upper == "C":
        return "Medium"
    return "High"


def _pattern_for_term(term: str) -> str:
    escaped = re.escape(term)
    escaped = escaped.replace(r"\ ", r"\s+")
    escaped = escaped.replace(r"\,", r"\s*,\s*")
    if re.fullmatch(r"[A-Za-z\-]+", term):
        return rf"\b{escaped}\b"
    return escaped


def _highlight_dangers(text: str, flaws: list[dict]) -> Markup:
    dangerous_terms = {
        flaw["term"]
        for flaw in flaws
        if flaw.get("severity") in {"high", "medium"}
    }
    if not dangerous_terms:
        return Markup(f"<pre class='policy-text'>{escape(text)}</pre>")

    patterns = sorted(
        (_pattern_for_term(term) for term in dangerous_terms),
        key=len,
        reverse=True,
    )
    combined_pattern = re.compile("(" + "|".join(patterns) + ")", flags=re.IGNORECASE)

    parts: list[str] = []
    cursor = 0
    for match in combined_pattern.finditer(text):
        start, end = match.span()
        if start > cursor:
            parts.append(str(escape(text[cursor:start])))
        parts.append(f"<mark class='danger-mark'>{escape(text[start:end])}</mark>")
        cursor = end
    if cursor < len(text):
        parts.append(str(escape(text[cursor:])))

    highlighted = "".join(parts)
    return Markup(f"<pre class='policy-text'>{highlighted}</pre>")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/test-key", methods=["GET", "POST"])
@app.route("/test_key.html", methods=["GET", "POST"])
def test_key_page():
    status = ""
    response_text = ""

    if request.method == "POST":
        load_dotenv()
        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            status = "❌ GEMINI_API_KEY not found in .env file."
        else:
            try:
                genai = importlib.import_module("google.genai")
            except Exception:
                status = "❌ Missing dependency: install google-genai."
                return render_template("test_key.html", status=status, response_text=response_text)

            try:
                client = genai.Client(api_key=api_key)
                last_error = None
                discovered_models = _candidate_models_from_api(client)
                models_to_try = discovered_models if discovered_models else MODEL_CANDIDATES

                for model_name in models_to_try:
                    try:
                        response = client.models.generate_content(
                            model=model_name,
                            contents="Say 'System Online' if you can read this.",
                        )
                        status = f"✅ API key works. Model: {model_name}"
                        response_text = getattr(response, "text", "(No text returned)")
                        break
                    except Exception as model_error:
                        last_error = model_error
                else:
                    raise last_error if last_error else RuntimeError("No model candidates succeeded.")
            except Exception as exc:
                status = f"❌ API request failed: {exc}"

    return render_template("test_key.html", status=status, response_text=response_text)


@app.route("/compare", methods=["GET", "POST"], endpoint="compare")
@app.route("/cookie-audit", methods=["GET", "POST"], endpoint="cookie_audit")
def compare_cookie_audit():
    site_url = ""
    policy_text = ""
    observed_cookies = ""

    report = None
    flaws = []
    highlighted_text = None
    grade = None

    cookie_result = None
    consent_state = "before_consent"

    policy_source_url = ""
    policy_source_label = ""
    policy_error = ""
    cookie_error = ""
    auto_message = ""
    include_breach_lookup = False
    breach_snapshot = None
    breach_error = ""
    breach_items: list[dict] = []
    breach_synopsis = ""
    breach_sources: list[str] = []
    breach_grade = ""
    breach_risk_level = ""
    final_grade = ""
    final_grade_risk = ""
    final_grade_components: list[dict] = []

    if request.method == "POST":
        site_url = request.form.get("site_url", "").strip()
        include_breach_lookup = request.form.get("include_breach_lookup") == "on"

        if site_url:
            if not site_url.startswith(("http://", "https://")):
                site_url = "https://" + site_url

            policy_fetch = fetch_policy_text_for_site(site_url)
            if policy_fetch.get("ok"):
                policy_text = policy_fetch.get("text", "")
                policy_source_url = policy_fetch.get("source_url", "")
                policy_source_label = policy_fetch.get("source_label", "")

                report = analyze_policy_text(policy_text)
                flaws = _extract_flaws(report)
                highlighted_text = _highlight_dangers(policy_text, flaws)
                grade = _privacy_grade(report.get("risk_score", 0))
            else:
                policy_error = policy_fetch.get("error", "Policy fetch failed.")

            cookie_fetch = auto_collect_cookies(site_url=site_url, consent_state=consent_state)
            if cookie_fetch.get("ok"):
                observed_cookies = "\n".join(cookie_fetch.get("cookie_names", []))
                auto_message = f"Auto-collected {cookie_fetch.get('count', 0)} cookies from {site_url}."
            else:
                cookie_error = cookie_fetch.get("error", "Cookie collection failed.")

            if observed_cookies:
                cookie_result = grade_cookie_truthfulness(
                    policy_text=policy_text,
                    observed_cookie_text=observed_cookies,
                    consent_state=consent_state,
                )

            if include_breach_lookup:
                breach_snapshot, breach_error = _generate_breach_snapshot(site_url)
                if breach_snapshot:
                    breach_items, breach_synopsis, breach_sources, breach_grade, breach_risk_level = _parse_breach_snapshot(breach_snapshot)

                if not breach_items or "generic domain" in breach_synopsis.lower():
                    legacy_snapshot, legacy_error = _generate_breach_snapshot_legacy(site_url)
                    if legacy_snapshot:
                        breach_snapshot = legacy_snapshot
                        breach_items, breach_synopsis, breach_sources, breach_grade, breach_risk_level = _parse_breach_snapshot(legacy_snapshot)
                        breach_error = ""
                    elif legacy_error and not breach_error:
                        breach_error = legacy_error

            if grade:
                final_grade_components.append({"label": "Policy", "grade": grade})
            if cookie_result and cookie_result.get("grade"):
                final_grade_components.append({"label": "Cookie", "grade": cookie_result.get("grade")})
            if include_breach_lookup and breach_grade:
                final_grade_components.append({"label": "Breach", "grade": breach_grade})

            if final_grade_components:
                avg_points = sum(_grade_to_points(item["grade"]) for item in final_grade_components) / len(final_grade_components)
                final_grade = _points_to_grade(avg_points)
                final_grade_risk = _grade_to_risk(final_grade)

    return render_template(
        "compare.html",
        site_url=site_url,
        policy_text=policy_text,
        policy_source_url=policy_source_url,
        policy_source_label=policy_source_label,
        policy_error=policy_error,
        report=report,
        flaws=flaws,
        highlighted_text=highlighted_text,
        grade=grade,
        observed_cookies=observed_cookies,
        consent_state=consent_state,
        auto_message=auto_message,
        cookie_error=cookie_error,
        cookie_result=cookie_result,
        include_breach_lookup=include_breach_lookup,
        breach_snapshot=breach_snapshot,
        breach_error=breach_error,
        breach_items=breach_items,
        breach_synopsis=breach_synopsis,
        breach_sources=breach_sources,
        breach_grade=breach_grade,
        breach_risk_level=breach_risk_level,
        final_grade=final_grade,
        final_grade_risk=final_grade_risk,
        final_grade_components=final_grade_components,
    )

if __name__ == "__main__":
    app.run(debug=True)
