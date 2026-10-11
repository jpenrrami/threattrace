from __future__ import annotations

import argparse
import csv
import ipaddress
import json
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import select

from threattrace.common.json_config import config_path, load_json_config
from threattrace.db.models import (
    AnalysisRun,
    IOCReport,
    Sample,
    SampleArtifact,
    SampleAttackTechnique,
    SampleBehaviorScore,
    SampleIoC,
    SampleSource,
)
from threattrace.db.session import session_scope
from threattrace.detection.noise import classify_noise
from threattrace.etl.ioc_engine.observability import build_detection_candidate

ROOT_DIR = Path(__file__).resolve().parents[3]
IO_EXPORT_CONFIG_PATH = config_path("detection", "ioc_export_rules.json")


@lru_cache(maxsize=1)
def _ioc_export_config() -> dict[str, Any]:
    return load_json_config(str(IO_EXPORT_CONFIG_PATH))


def _json_default(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"Unsupported JSON value: {type(value)!r}")


def _behavior_patterns_from_sample(sample_payload: dict[str, Any]) -> list[str]:
    patterns: set[str] = set()
    for source in (
        sample_payload.get("normalized_ioc", {}),
        sample_payload.get("threat_intel", {}),
    ):
        if not isinstance(source, dict):
            continue
        attack_patterns = source.get("attack_patterns", {})
        if not isinstance(attack_patterns, dict):
            continue
        patterns.update(str(key) for key, enabled in attack_patterns.items() if enabled)
    for item in sample_payload.get("attack_techniques", []):
        technique = item.get("technique")
        if technique:
            patterns.add(str(technique).lower())
    return sorted(patterns)


def _artifact_candidate_type(artifact_type: str, artifact_value: str) -> str | None:
    kind = artifact_type.lower().strip()
    value = artifact_value.strip()
    lowered = value.lower()
    if kind == "behavior_pattern":
        return artifact_value.lower().strip() or None
    if kind in {"ransom_notes"}:
        return "file"
    if kind in {"network_indicators", "suspicious_connections"}:
        if lowered.startswith(("http://", "https://")):
            return "url"
        host = lowered.rsplit(":", 1)[0] if ":" in lowered and lowered.count(":") == 1 else lowered
        try:
            ipaddress.ip_address(host.strip("[]"))
            return "ip"
        except ValueError:
            if "." in host and "\\" not in host and "/" not in host:
                return "domain"
        return None
    if any(token in kind for token in ("registry",)):
        return "registry"
    if any(token in kind for token in ("mutex",)):
        return "mutex"
    if any(token in kind for token in ("process", "service", "scheduled_task", "scheduledtasks", "lolbin", "command")):
        return "process"
    if any(token in kind for token in ("file", "ransom_note", "extension")):
        return "file"
    return None


def _build_aggregate_payload(
    rows: list[dict[str, Any]],
    *,
    min_confidence: float,
    ioc_type: str | None,
    endpoint_observable_only: bool,
    include_low_confidence: bool,
) -> dict[str, Any]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    behavior_counter: Counter[str] = Counter()

    for sample in rows:
        sample_ref = {
            "sample_id": sample["sample_id"],
            "sha256": sample["sha256"],
            "source": sample["source"],
            "dataset_role": sample["dataset_role"],
        }
        for ioc in sample.get("iocs", []):
            category = str(ioc.get("type") or "").lower()
            value = str(ioc.get("value") or "").strip()
            if not category or not value:
                continue
            if ioc_type and category != ioc_type:
                continue
            key = (category, value)
            if key not in grouped:
                grouped[key] = build_detection_candidate(
                    category=category,
                    value=value,
                    source=str(ioc.get("source") or "sample_iocs"),
                    sample_refs=[],
                )
            if ioc.get("confidence") is not None:
                grouped[key]["ranking_score"] = max(
                    float(grouped[key].get("ranking_score", 0)),
                    float(ioc["confidence"]),
                )
            grouped[key]["sample_refs"].append(sample_ref)

        for artifact in sample.get("artifacts", []):
            artifact_type = str(artifact.get("type") or "")
            artifact_value = str(artifact.get("value") or "").strip()
            category = _artifact_candidate_type(artifact_type, artifact_value)
            if not category or not artifact_value:
                continue
            if ioc_type and category != ioc_type and not (ioc_type == "behavior" and category == "behavior"):
                continue
            key = (category, artifact_value)
            if key not in grouped:
                grouped[key] = build_detection_candidate(
                    category=category,
                    value=artifact_value,
                    source=str(artifact.get("source") or f"sample_artifacts:{artifact_type}"),
                    sample_refs=[],
                )
            grouped[key]["sample_refs"].append(sample_ref)

        for pattern in _behavior_patterns_from_sample(sample):
            behavior_counter[pattern] += 1
            if ioc_type and ioc_type != "behavior":
                continue
            key = ("behavior", pattern)
            if key not in grouped:
                grouped[key] = build_detection_candidate(
                    category=pattern,
                    value=pattern,
                    source="attack_patterns",
                    sample_refs=[],
                )
            grouped[key]["sample_refs"].append(sample_ref)

    raw_iocs: list[dict[str, Any]] = []
    research_iocs: list[dict[str, Any]] = []
    detection_iocs: list[dict[str, Any]] = []
    endpoint_iocs: list[dict[str, Any]] = []
    excluded_iocs: list[dict[str, Any]] = []
    for candidate in grouped.values():
        sample_refs = candidate.get("sample_refs", [])
        candidate["sample_count"] = len({ref["sample_id"] for ref in sample_refs})
        candidate["first_seen"] = None
        candidate["last_seen"] = None
        raw_iocs.append(candidate)
        research_decision = classify_noise(candidate, layer="detection")
        if research_decision.reason == "attack_technique_not_ioc":
            excluded_iocs.append({**candidate, "tier": "research", "rejection_reason": research_decision.reason})
            continue
        research_iocs.append(candidate)
        if research_decision.action == "reject":
            excluded_iocs.append({**candidate, "tier": "detection", "rejection_reason": research_decision.reason})
            continue
        if endpoint_observable_only and not candidate.get("endpoint_observable"):
            continue
        if not include_low_confidence and candidate.get("ranking_score", 0) < min_confidence:
            continue
        detection_iocs.append(candidate)
        endpoint_decision = classify_noise(candidate, layer="endpoint")
        if not candidate.get("endpoint_observable"):
            excluded_iocs.append({**candidate, "tier": "endpoint", "rejection_reason": "missing_endpoint_context"})
            continue
        if endpoint_decision.action == "reject":
            excluded_iocs.append({**candidate, "tier": "endpoint", "rejection_reason": endpoint_decision.reason})
            continue
        endpoint_iocs.append(candidate)

    for items in (raw_iocs, research_iocs, detection_iocs, endpoint_iocs):
        items.sort(
            key=lambda item: (
                -int(item.get("sample_count", 0)),
                -float(item.get("ranking_score", 0)),
                str(item.get("category", "")),
                str(item.get("value", "")),
            )
        )
    excluded_iocs.sort(
        key=lambda item: (
            -int(item.get("sample_count", 0)),
            _ioc_export_config()["rejection_reason_order"].index(str(item.get("rejection_reason")))
            if str(item.get("rejection_reason")) in _ioc_export_config()["rejection_reason_order"]
            else len(_ioc_export_config()["rejection_reason_order"]),
            str(item.get("value", "")),
        )
    )
    velociraptor_candidates = [
        item
        for item in endpoint_iocs
        if (
            "velociraptor" in item.get("observability", [])
            or str(item.get("suggested_detector", "")).startswith("velociraptor")
        )
        and classify_noise(item, layer="velociraptor").action == "keep"
    ]
    indicators = detection_iocs
    rejection_counts = Counter(str(item.get("rejection_reason") or "unknown") for item in excluded_iocs)
    return {
        "indicators": indicators,
        "raw_iocs": raw_iocs,
        "research_iocs": research_iocs,
        "detection_iocs": detection_iocs,
        "endpoint_iocs": endpoint_iocs,
        "excluded_iocs": excluded_iocs,
        "behavioral_patterns": [
            {"pattern": pattern, "sample_count": count}
            for pattern, count in behavior_counter.most_common()
        ],
        "velociraptor_candidates": velociraptor_candidates,
        "noise_metrics": {
            "rejection_reasons": [
                {"reason": reason, "count": count}
                for reason, count in rejection_counts.most_common()
            ],
            "raw_to_detection_reduction_pct": round(
                (1 - (len(detection_iocs) / len(raw_iocs))) * 100,
                2,
            )
            if raw_iocs
            else 0.0,
            "detection_to_endpoint_reduction_pct": round(
                (1 - (len(endpoint_iocs) / len(detection_iocs))) * 100,
                2,
            )
            if detection_iocs
            else 0.0,
            "endpoint_to_velociraptor_reduction_pct": round(
                (1 - (len(velociraptor_candidates) / len(endpoint_iocs))) * 100,
                2,
            )
            if endpoint_iocs
            else 0.0,
        },
        "summary": {
            "samples": len(rows),
            "raw_iocs": len(raw_iocs),
            "research_iocs": len(research_iocs),
            "detection_iocs": len(detection_iocs),
            "endpoint_iocs": len(endpoint_iocs),
            "excluded_iocs": len(excluded_iocs),
            "indicators": len(indicators),
            "velociraptor_candidates": len(velociraptor_candidates),
            "ioc_type_filter": ioc_type,
            "min_confidence": min_confidence,
            "endpoint_observable_only": endpoint_observable_only,
        },
    }


def export_detection_iocs(
    limit: int | None = None,
    *,
    min_confidence: float = 0.0,
    ioc_type: str | None = None,
    endpoint_observable_only: bool = False,
    include_low_confidence: bool = True,
    include_samples: bool = True,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with session_scope() as session:
        report_rows = session.execute(
            select(IOCReport, AnalysisRun, Sample)
            .join(AnalysisRun, AnalysisRun.id == IOCReport.analysis_run_id)
            .join(Sample, Sample.id == AnalysisRun.sample_id)
            .order_by(IOCReport.updated_at.desc().nullslast(), IOCReport.created_at.desc())
            .limit(limit)
        ).all()
        sample_ids = [sample.id for _, _, sample in report_rows]
        iocs_by_sample: dict[int, list[SampleIoC]] = defaultdict(list)
        artifacts_by_sample: dict[int, list[SampleArtifact]] = defaultdict(list)
        techniques_by_sample: dict[int, list[SampleAttackTechnique]] = defaultdict(list)
        source_by_sample: dict[int, SampleSource] = {}
        score_by_sample = {
            score.sample_id: score
            for score in session.execute(
                select(SampleBehaviorScore).where(SampleBehaviorScore.sample_id.in_(sample_ids))
            ).scalars()
        } if sample_ids else {}
        for item in session.execute(select(SampleIoC).where(SampleIoC.sample_id.in_(sample_ids))).scalars() if sample_ids else []:
            iocs_by_sample[item.sample_id].append(item)
        for item in session.execute(select(SampleArtifact).where(SampleArtifact.sample_id.in_(sample_ids))).scalars() if sample_ids else []:
            artifacts_by_sample[item.sample_id].append(item)
        for item in session.execute(select(SampleAttackTechnique).where(SampleAttackTechnique.sample_id.in_(sample_ids))).scalars() if sample_ids else []:
            techniques_by_sample[item.sample_id].append(item)
        for item in session.execute(
            select(SampleSource).where(SampleSource.sample_id.in_(sample_ids)).order_by(SampleSource.created_at.desc())
        ).scalars() if sample_ids else []:
            source_by_sample.setdefault(item.sample_id, item)

        for report, _, sample in report_rows:
            iocs = iocs_by_sample.get(sample.id, [])
            artifacts = artifacts_by_sample.get(sample.id, [])
            techniques = techniques_by_sample.get(sample.id, [])
            scores = score_by_sample.get(sample.id)
            source = source_by_sample.get(sample.id)
            rows.append(
                {
                    "sample_id": sample.id,
                    "sha256": sample.sha256,
                    "source": source.source if source else "malwarebazaar",
                    "dataset_role": source.dataset_role if source else "train",
                    "family_hint": source.family_hint if source else None,
                    "sample_category": report.sample_category,
                    "family_hints": report.family_hints or {},
                    "ioc_types": sorted({ioc.type for ioc in iocs if ioc.type}),
                    "iocs": [
                        {
                            "type": ioc.type,
                            "value": ioc.value,
                            "source": ioc.source,
                            "confidence": float(ioc.confidence) if ioc.confidence is not None else None,
                        }
                        for ioc in iocs
                    ],
                    "artifacts": [
                        {
                            "type": item.artifact_type,
                            "value": item.artifact_value,
                            "source": item.source,
                            "confidence": float(item.confidence) if item.confidence is not None else None,
                        }
                        for item in artifacts
                    ],
                    "attack_techniques": [{"technique": item.technique, "category": item.category} for item in techniques],
                    "behavior_scores": {
                        "persistence_score": getattr(scores, "persistence_score", None),
                        "severity_score": getattr(scores, "severity_score", None),
                        "confidence_score": getattr(scores, "confidence_score", None),
                        "ransomware_score": getattr(scores, "ransomware_score", None),
                        "credential_score": getattr(scores, "credential_score", None),
                        "defense_evasion_score": getattr(scores, "defense_evasion_score", None),
                    },
                    "normalized_ioc": report.normalized_ioc or {},
                    "threat_intel": report.threat_intel or {},
                }
            )
    aggregate = _build_aggregate_payload(
        rows,
        min_confidence=min_confidence,
        ioc_type=ioc_type,
        endpoint_observable_only=endpoint_observable_only,
        include_low_confidence=include_low_confidence,
    )
    payload = {"generated": len(rows), **aggregate}
    if include_samples:
        payload["samples"] = rows
    return payload


def write_detection_iocs(payload: dict[str, Any], output_json: Path, output_csv: Path) -> None:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_json.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False, default=_json_default)
        handle.write("\n")
    with output_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "category",
                "value",
                "type",
                "confidence",
                "sample_count",
                "source",
                "endpoint_observable",
                "observability",
                "suggested_detector",
                "false_positive_risk",
                "generalization_value",
            ],
        )
        writer.writeheader()
        for indicator in payload.get("indicators", []):
            writer.writerow(
                {
                    "category": indicator.get("category"),
                    "value": indicator.get("value"),
                    "type": indicator.get("type"),
                    "confidence": indicator.get("confidence"),
                    "sample_count": indicator.get("sample_count"),
                    "source": indicator.get("source"),
                    "endpoint_observable": indicator.get("endpoint_observable"),
                    "observability": ",".join(indicator.get("observability", [])),
                    "suggested_detector": indicator.get("suggested_detector"),
                    "false_positive_risk": indicator.get("false_positive_risk"),
                    "generalization_value": indicator.get("generalization_value"),
                }
            )


def write_detection_bundle(payload: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    write_detection_iocs(payload, output_dir / "iocs.json", output_dir / "iocs.csv")
    for name in ("behavioral_patterns", "velociraptor_candidates", "summary"):
        (output_dir / f"{name}.json").write_text(
            json.dumps(payload.get(name, {}), indent=2, ensure_ascii=False, default=_json_default) + "\n",
            encoding="utf-8",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export detection IoCs for Velociraptor/validation workflows")
    parser.add_argument("--output-json")
    parser.add_argument("--output-csv")
    parser.add_argument("--output-dir")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--min-confidence", type=float, default=0.0)
    parser.add_argument("--ioc-type", choices=["ip", "domain", "url", "file", "registry", "mutex", "process", "behavior"])
    parser.add_argument("--endpoint-observable-only", action="store_true")
    parser.add_argument("--include-low-confidence", action="store_true")
    parser.add_argument("--include-samples", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not args.output_dir and (not args.output_json or not args.output_csv):
        raise SystemExit("Provide --output-dir or both --output-json and --output-csv")
    payload = export_detection_iocs(
        limit=args.limit,
        min_confidence=args.min_confidence,
        ioc_type=args.ioc_type,
        endpoint_observable_only=args.endpoint_observable_only,
        include_low_confidence=args.include_low_confidence,
        include_samples=args.include_samples,
    )
    outputs: dict[str, Any] = {"generated": payload["generated"], "summary": payload.get("summary", {})}
    if args.output_dir:
        write_detection_bundle(payload, Path(args.output_dir))
        outputs["output_dir"] = args.output_dir
    else:
        write_detection_iocs(payload, Path(args.output_json), Path(args.output_csv))
        outputs["output_json"] = args.output_json
        outputs["output_csv"] = args.output_csv
    print(json.dumps(outputs, indent=2))


if __name__ == "__main__":
    main()
