"""Company context extraction and triage guidance."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

import httpx

from app.config import settings


INDUSTRY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "fintech": ("payments", "banking", "wallet", "trading", "fintech", "card"),
    "ecommerce": ("shop", "cart", "checkout", "order", "inventory", "store"),
    "saas": ("platform", "dashboard", "workspace", "subscription", "api"),
    "healthcare": ("patient", "clinic", "ehr", "medical", "healthcare", "hipaa"),
    "education": ("student", "course", "campus", "learning", "school"),
}

BUSINESS_MODEL_KEYWORDS: dict[str, tuple[str, ...]] = {
    "b2b": ("enterprise", "team", "organization", "business"),
    "b2c": ("consumer", "customers", "users", "shop"),
    "marketplace": ("seller", "buyer", "vendors", "marketplace"),
    "subscription": ("pricing", "monthly", "annual", "plan", "billing"),
}

ATTACK_SURFACE_BY_INDUSTRY: dict[str, list[str]] = {
    "fintech": [
        "Authentication and MFA flows",
        "Payment APIs and transfer endpoints",
        "Account takeover paths and password reset",
        "PII exposure in profile and statement routes",
    ],
    "ecommerce": [
        "Checkout and payment webhooks",
        "Cart and coupon logic",
        "Account and order history endpoints",
        "Admin/catalog upload panels",
    ],
    "saas": [
        "SSO/OAuth and session management",
        "Tenant isolation and IDOR in API routes",
        "Admin consoles and privileged actions",
        "Billing/subscription management endpoints",
    ],
    "healthcare": [
        "Patient record and file upload routes",
        "Authorization around records and notes",
        "Staff/admin portals",
        "PII/PHI leakage via APIs",
    ],
    "education": [
        "Student profile and grading APIs",
        "Teacher/admin panels",
        "File upload and assignment workflow",
        "SSO and role boundary checks",
    ],
}


@dataclass
class CompanyContextResult:
    source_url: str
    description_raw: str
    industry: str
    business_model: str
    keywords: list[str]
    likely_attack_surface: list[str]
    where_to_look_first: str
    summary_hash: str


def _strip_html(html: str) -> str:
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _extract_description(html: str, fallback_host: str) -> str:
    meta = re.search(
        r'(?is)<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
        html,
    )
    if meta:
        return meta.group(1).strip()[:1200]

    title = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    text = _strip_html(html)
    if title:
        return f"{title.group(1).strip()}. {text[:900]}".strip()
    return f"{fallback_host}. {text[:900]}".strip()


def _top_keywords(text: str, limit: int = 12) -> list[str]:
    tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9]{3,}", text.lower())
    stop = {
        "with", "that", "this", "from", "have", "your", "about", "more", "into",
        "their", "will", "than", "such", "also", "only", "using", "platform",
        "service", "services", "company", "business", "home", "page",
    }
    counts: dict[str, int] = {}
    for token in tokens:
        if token in stop:
            continue
        counts[token] = counts.get(token, 0) + 1
    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return [k for k, _ in ranked[:limit]]


def _score_labels(text: str, mapping: dict[str, Iterable[str]], default: str) -> str:
    text_lower = text.lower()
    scores: dict[str, int] = {}
    for label, words in mapping.items():
        scores[label] = sum(1 for w in words if w in text_lower)
    best = max(scores, key=scores.get)
    if scores[best] <= 0:
        return default
    return best


def _where_to_look_first(industry: str, keywords: list[str]) -> str:
    focus = ATTACK_SURFACE_BY_INDUSTRY.get(industry, [
        "Authentication and session handling",
        "Admin and privileged endpoints",
        "File upload and parsing flows",
        "PII and data export APIs",
    ])
    key_hint = ", ".join(keywords[:5]) if keywords else "auth, admin, billing, api"
    return (
        "Prioritize paths tied to business critical actions. "
        f"Start with: {focus[0]}; then review {focus[1]}. "
        f"Keyword-driven hunt seed: {key_hint}."
    )


def _similarity(a: str, b: str) -> float:
    at = set(re.findall(r"[a-zA-Z0-9]{3,}", a.lower()))
    bt = set(re.findall(r"[a-zA-Z0-9]{3,}", b.lower()))
    if not at and not bt:
        return 1.0
    union = at | bt
    if not union:
        return 0.0
    return len(at & bt) / len(union)


def context_similarity(previous_description: str, current_description: str) -> float:
    return round(_similarity(previous_description, current_description), 3)


def generate_company_context(url: str) -> CompanyContextResult:
    host = urlparse(url).hostname or url
    html = ""
    with httpx.Client(
        timeout=settings.crawl_timeout,
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
        verify=False,
    ) as client:
        try:
            resp = client.get(url)
            html = resp.text[:250000]
            source_url = str(resp.url)
        except Exception:
            source_url = url

    description = _extract_description(html or "", host)
    industry = _score_labels(description, INDUSTRY_KEYWORDS, default="general")
    business_model = _score_labels(description, BUSINESS_MODEL_KEYWORDS, default="unknown")
    keywords = _top_keywords(description)
    likely_attack_surface = ATTACK_SURFACE_BY_INDUSTRY.get(industry, [
        "Authentication and role authorization",
        "Admin panels and internal tooling",
        "PII data handling APIs",
    ])
    where_to_look_first = _where_to_look_first(industry, keywords)
    summary_hash = hashlib.sha256(
        f"{industry}|{business_model}|{description[:1000]}".encode("utf-8")
    ).hexdigest()[:32]
    return CompanyContextResult(
        source_url=source_url,
        description_raw=description,
        industry=industry,
        business_model=business_model,
        keywords=keywords,
        likely_attack_surface=likely_attack_surface,
        where_to_look_first=where_to_look_first,
        summary_hash=summary_hash,
    )
