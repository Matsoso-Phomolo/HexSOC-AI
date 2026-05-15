"""Lightweight campaign clustering over computed attack chains."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any


def build_campaign_clusters(chains: list[dict[str, Any]], *, limit: int = 50) -> list[dict[str, Any]]:
    """Group related attack chains into bounded campaign summaries."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for chain in chains:
        key = _campaign_key(chain)
        groups[key].append(chain)

    campaigns = [_build_campaign(key, grouped) for key, grouped in groups.items()]
    campaigns.sort(key=lambda item: (item["max_risk_score"], item["chain_count"]), reverse=True)
    return campaigns[: max(1, min(limit, 200))]


def _campaign_key(chain: dict[str, Any]) -> str:
    source_ip = chain.get("primary_source_ip")
    if source_ip:
        return f"source_ip:{source_ip}"
    techniques = chain.get("mitre_techniques") or []
    if techniques:
        return f"technique:{techniques[0]}"
    users = chain.get("usernames") or []
    if users:
        return f"user:{users[0]}"
    return chain.get("primary_group") or chain["chain_id"]


def _build_campaign(key: str, chains: list[dict[str, Any]]) -> dict[str, Any]:
    source_ips = _unique_many(chain.get("related_source_ips") or [] for chain in chains)
    users = _unique_many(chain.get("usernames") or [] for chain in chains)
    techniques = _unique_many(chain.get("mitre_techniques") or [] for chain in chains)
    tactics = _unique_many(chain.get("mitre_tactics") or [] for chain in chains)
    stages = _unique_many(chain.get("stages") or [] for chain in chains)
    assets = _unique_assets(chains)
    risks = [chain.get("risk_score") or 0 for chain in chains]
    first_seen_values = [chain["timeline"].get("first_seen") for chain in chains if chain.get("timeline")]
    last_seen_values = [chain["timeline"].get("last_seen") for chain in chains if chain.get("timeline")]
    campaign_id = f"campaign:{hashlib.sha1(key.encode('utf-8')).hexdigest()[:16]}"
    return {
        "campaign_id": campaign_id,
        "cluster_key": key,
        "title": _campaign_title(key, len(chains)),
        "chain_count": len(chains),
        "chain_ids": [chain["chain_id"] for chain in chains[:50]],
        "source_ips": source_ips[:20],
        "usernames": users[:20],
        "affected_assets": assets[:20],
        "mitre_techniques": techniques[:20],
        "mitre_tactics": tactics[:20],
        "stages": stages[:20],
        "max_risk_score": max(risks, default=0),
        "average_risk_score": round(sum(risks) / len(risks), 2) if risks else 0,
        "classification": _classify(max(risks, default=0)),
        "first_seen": min(first_seen_values) if first_seen_values else None,
        "last_seen": max(last_seen_values) if last_seen_values else None,
        "summary": f"{len(chains)} attack chain(s) share {key.replace(':', ' ')}.",
    }


def _campaign_title(key: str, count: int) -> str:
    label = key.replace("source_ip:", "Source IP ").replace("technique:", "MITRE ").replace("user:", "User ")
    return f"{label} campaign candidate ({count} chains)"


def _classify(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "suspicious"
    return "low"


def _unique_many(values: Any) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for group in values:
        for value in group:
            if value is not None and value not in seen:
                seen.add(value)
                result.append(value)
    return result


def _unique_assets(chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[int] = set()
    result: list[dict[str, Any]] = []
    for chain in chains:
        for asset in chain.get("affected_assets") or []:
            asset_id = asset.get("id")
            if asset_id is not None and asset_id not in seen:
                seen.add(asset_id)
                result.append(asset)
    return result
