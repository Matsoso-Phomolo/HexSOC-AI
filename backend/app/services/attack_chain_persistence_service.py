"""Persist computed attack-chain intelligence as stable investigation objects."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy.orm import Session

from app.db import models
from app.services.campaign_cluster_engine import build_campaign_clusters

logger = logging.getLogger(__name__)


def persist_attack_chains(db: Session, computed_chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Upsert computed chains and timeline steps, returning API-safe records."""
    return materialize_attack_chains(db, computed_chains)["chains"]


def materialize_attack_chains(db: Session, computed_chains: list[dict[str, Any]]) -> dict[str, Any]:
    """Persist computed candidates with per-record isolation and materialization stats."""
    persisted: list[dict[str, Any]] = []
    chain_models: list[models.AttackChain] = []
    successful_candidates: list[dict[str, Any]] = []
    persistence_errors: list[dict[str, Any]] = []
    steps_persisted = 0
    campaigns_persisted = 0

    logger.info("Attack-chain persistence received %s computed candidates", len(computed_chains))

    for index, candidate in enumerate(computed_chains):
        try:
            with db.begin_nested():
                chain = upsert_attack_chain(db, candidate)
                db.flush()
                step_count = persist_attack_chain_steps(db, chain, candidate.get("timeline_steps") or [])
                db.flush()
            chain_models.append(chain)
            successful_candidates.append(candidate)
            steps_persisted += step_count
            persisted.append(serialize_attack_chain(chain))
            logger.info(
                "Attack-chain candidate materialized index=%s chain_id=%s steps=%s fingerprint=%s",
                index,
                chain.id,
                step_count,
                chain.stable_fingerprint,
            )
        except Exception as exc:
            logger.exception("Skipping invalid attack-chain candidate index=%s: %s", index, exc)
            persistence_errors.append(
                {
                    "index": index,
                    "chain_id": candidate.get("chain_id"),
                    "primary_group": candidate.get("primary_group"),
                    "error": exc.__class__.__name__,
                }
            )

    try:
        campaign_inputs = [
            _candidate_with_persisted_id(item, chain_models[index])
            for index, item in enumerate(successful_candidates)
        ]
        campaigns = build_campaign_clusters(campaign_inputs, limit=50)
        with db.begin_nested():
            campaign_models = persist_campaign_clusters(db, campaigns)
            db.flush()
        campaigns_persisted = len(campaign_models)
        logger.info("Attack-chain campaign materialization inserted_or_updated=%s", campaigns_persisted)
    except Exception as exc:
        logger.exception("Campaign cluster materialization failed; preserving persisted chains: %s", exc)
        persistence_errors.append({"index": None, "chain_id": None, "primary_group": "campaign_clusters", "error": exc.__class__.__name__})

    logger.info(
        "Attack-chain materialization complete generated=%s persisted=%s steps=%s campaigns=%s errors=%s",
        len(computed_chains),
        len(persisted),
        steps_persisted,
        campaigns_persisted,
        len(persistence_errors),
    )
    return {
        "chains_generated": len(computed_chains),
        "chains_persisted": len(persisted),
        "steps_persisted": steps_persisted,
        "campaigns_persisted": campaigns_persisted,
        "persistence_errors": persistence_errors,
        "chains": persisted,
    }


def upsert_attack_chain(db: Session, candidate: dict[str, Any]) -> models.AttackChain:
    """Create or update one persistent chain using a stable fingerprint."""
    chain_key = _chain_key(candidate)
    fingerprint = _fingerprint(chain_key)
    chain = db.query(models.AttackChain).filter(models.AttackChain.stable_fingerprint == fingerprint).first()
    signature = _change_signature(candidate)
    existing_signature = None
    if chain and isinstance(chain.related_iocs, dict):
        existing_signature = chain.related_iocs.get("change_signature")

    if chain is None:
        chain = models.AttackChain(
            chain_key=chain_key,
            stable_fingerprint=fingerprint,
            status="open",
            version=1,
        )
        db.add(chain)
    elif existing_signature and existing_signature != signature:
        chain.version = (chain.version or 1) + 1

    source_type, source_value = _source_parts(candidate)
    timeline = candidate.get("timeline") or {}
    chain.title = _truncate(candidate.get("title") or "Attack chain", 255)
    chain.classification = candidate.get("classification") or "suspicious"
    chain.risk_score = int(candidate.get("risk_score") or 0)
    chain.confidence = int(candidate.get("confidence") or 0)
    chain.source_type = source_type
    chain.source_value = _truncate(source_value, 255)
    chain.stage_count = len(candidate.get("stages") or [])
    chain.event_count = int((candidate.get("related_events") or {}).get("count") or 0)
    chain.alert_count = int((candidate.get("related_alerts") or {}).get("count") or 0)
    chain.first_seen = _parse_datetime(timeline.get("first_seen")) or chain.first_seen
    chain.last_seen = _parse_datetime(timeline.get("last_seen")) or chain.last_seen
    chain.mitre_techniques = _safe_list(candidate.get("mitre_techniques"))[:50]
    chain.mitre_tactics = _safe_list(candidate.get("mitre_tactics"))[:50]
    chain.related_assets = _safe_json(_safe_list(candidate.get("affected_assets"))[:50])
    chain.related_users = _safe_list(candidate.get("usernames"))[:50]
    chain.related_iocs = {
        **_safe_dict(candidate.get("related_iocs")),
        "change_signature": signature,
        "stages": _safe_list(candidate.get("stages"))[:50],
    }
    chain.summary = timeline.get("summary") or candidate.get("recommended_action")
    return chain


def persist_attack_chain_steps(db: Session, chain: models.AttackChain, steps: list[dict[str, Any]]) -> int:
    """Replace timeline steps for one chain with current computed ordering."""
    if chain.id is None:
        db.flush()
    db.query(models.AttackChainStep).filter(models.AttackChainStep.attack_chain_id == chain.id).delete()
    inserted = 0
    for index, step in enumerate(steps[:200]):
        entity_type = step.get("entity_type")
        entity_id = step.get("entity_id")
        db.add(
            models.AttackChainStep(
                attack_chain_id=chain.id,
                step_index=index,
                timestamp=_parse_datetime(step.get("timestamp")),
                stage=step.get("attack_stage"),
                event_type=step.get("event_type"),
                severity=step.get("severity"),
                mitre_technique=step.get("mitre_technique") or step.get("mitre_technique_id"),
                mitre_tactic=step.get("mitre_tactic"),
                hostname=step.get("hostname"),
                username=step.get("username"),
                source_ip=step.get("source_ip"),
                destination_ip=step.get("destination_ip"),
                event_id=_safe_int(entity_id) if entity_type == "event" else None,
                alert_id=_safe_int(entity_id) if entity_type == "alert" else None,
                description=step.get("summary") or step.get("title"),
                confidence=_safe_int(step.get("confidence")),
                step_metadata=_safe_json({key: value for key, value in step.items() if key not in {"summary"}}),
            )
        )
        inserted += 1
    return inserted


def persist_campaign_clusters(db: Session, campaigns: list[dict[str, Any]]) -> list[models.CampaignCluster]:
    """Upsert lightweight campaign clusters from current persisted chains."""
    persisted: list[models.CampaignCluster] = []
    for campaign in campaigns:
        key = campaign.get("cluster_key") or campaign.get("campaign_id")
        fingerprint = _fingerprint(str(key))
        row = db.query(models.CampaignCluster).filter(models.CampaignCluster.stable_fingerprint == fingerprint).first()
        if row is None:
            row = models.CampaignCluster(campaign_key=_truncate(str(key), 255), stable_fingerprint=fingerprint)
            db.add(row)
        row.title = _truncate(campaign.get("title") or "Campaign cluster", 255)
        row.classification = campaign.get("classification") or "suspicious"
        row.risk_score = int(campaign.get("max_risk_score") or 0)
        row.chain_count = int(campaign.get("chain_count") or 0)
        row.shared_iocs = _safe_json(_safe_list(campaign.get("shared_iocs"))[:50])
        row.shared_source_ips = _safe_list(campaign.get("source_ips"))[:50]
        row.shared_assets = _safe_json(_safe_list(campaign.get("affected_assets"))[:50])
        row.shared_users = _safe_list(campaign.get("usernames"))[:50]
        row.shared_techniques = _safe_list(campaign.get("mitre_techniques"))[:50]
        row.first_seen = _parse_datetime(campaign.get("first_seen")) or row.first_seen
        row.last_seen = _parse_datetime(campaign.get("last_seen")) or row.last_seen
        row.summary = campaign.get("summary")
        persisted.append(row)
    return persisted


def serialize_attack_chain(chain: models.AttackChain) -> dict[str, Any]:
    """Convert a persistent chain to the dashboard API shape."""
    return {
        "id": chain.id,
        "chain_id": str(chain.id),
        "stable_fingerprint": chain.stable_fingerprint,
        "title": chain.title,
        "classification": _safe_scalar(chain.classification, "suspicious"),
        "risk_score": int(chain.risk_score or 0),
        "confidence": int(chain.confidence or 0),
        "status": _safe_scalar(chain.status, "open"),
        "primary_group": f"{chain.source_type}:{chain.source_value}" if chain.source_type and chain.source_value else chain.chain_key,
        "primary_source_ip": chain.source_value if chain.source_type == "source_ip" else None,
        "source_type": chain.source_type,
        "source_value": chain.source_value,
        "related_source_ips": [chain.source_value] if chain.source_type == "source_ip" and chain.source_value else [],
        "usernames": _safe_list(chain.related_users),
        "affected_assets": _safe_list(chain.related_assets),
        "related_events": {"count": chain.event_count, "ids": []},
        "related_alerts": {"count": chain.alert_count, "ids": []},
        "related_iocs": _safe_dict(chain.related_iocs, default={"count": 0}),
        "stages": _steps_from_count(chain),
        "mitre_tactics": _safe_list(chain.mitre_tactics),
        "mitre_techniques": _safe_list(chain.mitre_techniques),
        "timeline": {
            "total_steps": int(chain.stage_count or 0),
            "first_seen": _iso(chain.first_seen),
            "last_seen": _iso(chain.last_seen),
            "stages": _steps_from_count(chain),
            "highest_severity": _safe_scalar(chain.classification, "suspicious"),
            "summary": chain.summary,
        },
        "severity": _safe_scalar(chain.classification, "suspicious"),
        "recommended_action": chain.summary,
        "version": int(chain.version or 1),
    }


def serialize_attack_chain_step(step: models.AttackChainStep) -> dict[str, Any]:
    """Convert a persistent chain step into the existing timeline response shape."""
    return {
        "step_id": f"step:{step.id}",
        "entity_type": "event" if step.event_id else "alert" if step.alert_id else "step",
        "entity_id": step.event_id or step.alert_id or step.id,
        "timestamp": _iso(step.timestamp),
        "event_type": step.event_type,
        "title": step.description,
        "severity": _safe_scalar(step.severity, "info"),
        "attack_stage": _safe_scalar(step.stage, "unknown"),
        "mitre_tactic": _safe_scalar(step.mitre_tactic),
        "mitre_technique": _safe_scalar(step.mitre_technique),
        "mitre_technique_id": _safe_scalar(step.mitre_technique),
        "hostname": step.hostname,
        "username": step.username,
        "source_ip": step.source_ip,
        "destination_ip": step.destination_ip,
        "summary": step.description,
    }


def serialize_campaign(campaign: models.CampaignCluster) -> dict[str, Any]:
    """Convert a persistent campaign cluster to a dashboard API shape."""
    return {
        "id": campaign.id,
        "campaign_id": str(campaign.id),
        "stable_fingerprint": campaign.stable_fingerprint,
        "cluster_key": campaign.campaign_key,
        "title": campaign.title,
        "classification": _safe_scalar(campaign.classification, "suspicious"),
        "max_risk_score": int(campaign.risk_score or 0),
        "risk_score": int(campaign.risk_score or 0),
        "chain_count": int(campaign.chain_count or 0),
        "source_ips": _safe_list(campaign.shared_source_ips),
        "shared_iocs": _safe_list(campaign.shared_iocs),
        "affected_assets": _safe_list(campaign.shared_assets),
        "usernames": _safe_list(campaign.shared_users),
        "mitre_techniques": _safe_list(campaign.shared_techniques),
        "first_seen": _iso(campaign.first_seen),
        "last_seen": _iso(campaign.last_seen),
        "summary": campaign.summary,
    }


def _candidate_with_persisted_id(candidate: dict[str, Any], chain: models.AttackChain) -> dict[str, Any]:
    next_candidate = dict(candidate)
    next_candidate["chain_id"] = str(chain.id)
    return next_candidate


def _chain_key(candidate: dict[str, Any]) -> str:
    source_type, source_value = _source_parts(candidate)
    return _truncate(f"{source_type}:{source_value}", 255)


def _source_parts(candidate: dict[str, Any]) -> tuple[str, str]:
    primary = candidate.get("primary_group") or ""
    if ":" in primary:
        source_type, source_value = primary.split(":", 1)
        return source_type, source_value
    if candidate.get("primary_source_ip"):
        return "source_ip", candidate["primary_source_ip"]
    return "mixed", primary or candidate.get("title") or "unknown"


def _change_signature(candidate: dict[str, Any]) -> str:
    parts = [
        str(candidate.get("risk_score") or 0),
        ",".join(str(item) for item in (candidate.get("related_events") or {}).get("ids", [])),
        ",".join(str(item) for item in (candidate.get("related_alerts") or {}).get("ids", [])),
        ",".join(candidate.get("stages") or []),
    ]
    return _fingerprint("|".join(parts))


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _truncate(value: Any, limit: int) -> str:
    text = str(value or "")
    return text[:limit]


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _safe_scalar(value: Any, default: Any = None) -> Any:
    if isinstance(value, Enum):
        return value.value
    return default if value is None else value


def _safe_dict(value: Any, default: dict[str, Any] | None = None) -> dict[str, Any]:
    if isinstance(value, dict):
        return {str(key): _safe_json(item) for key, item in value.items()}
    return default or {}


def _safe_json(value: Any) -> Any:
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _safe_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, set):
        return sorted(_safe_json(item) for item in value)
    return value


def _steps_from_count(chain: models.AttackChain) -> list[str]:
    if isinstance(chain.related_iocs, dict) and chain.related_iocs.get("stages"):
        return _safe_list(chain.related_iocs["stages"])
    return []


def _safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]
