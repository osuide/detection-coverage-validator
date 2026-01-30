"""Quick scan service — orchestrates parse, map, and analyse.

No database access. No authentication. All ephemeral.
Coverage calculation functions (build_technique_coverage_from_mappings,
calculate_tactic_summary) are inlined here to avoid a separate file.
"""

import structlog

from app.analyzers.coverage_calculator import TechniqueCoverageInfo
from app.analyzers.gap_analyzer import GapAnalyzer
from app.core.cache import get_cached, mitre_techniques_key
from app.mappers.pattern_mapper import MappingResult, PatternMapper
from app.parsers.terraform_hcl_parser import parse_terraform_content, ParseResult

logger = structlog.get_logger()

# Pre-compromise tactics excluded from quick scan results (not cloud-detectable)
_PRE_COMPROMISE_TACTICS = {"TA0043", "TA0042"}  # Reconnaissance, Resource Development


# ---------------------------------------------------------------------------
# Coverage functions (standalone, no DB dependency)
# ---------------------------------------------------------------------------


def build_technique_coverage_from_mappings(
    all_techniques: list[dict],
    mappings: list[MappingResult],
) -> list[TechniqueCoverageInfo]:
    """Build technique coverage info from mapping results.

    Args:
        all_techniques: List of dicts with keys: id, technique_id, name,
                       platforms, tactic_id, tactic_name, is_subtechnique
                       (as cached by get_cached_techniques in cache.py).
        mappings: MappingResult objects from PatternMapper.

    Returns:
        List of TechniqueCoverageInfo for all techniques.
    """
    technique_mappings: dict[str, list[MappingResult]] = {}
    for m in mappings:
        technique_mappings.setdefault(m.technique_id, []).append(m)

    coverage: list[TechniqueCoverageInfo] = []

    for tech in all_techniques:
        tech_id = tech["technique_id"]
        tech_mappings = technique_mappings.get(tech_id, [])

        if tech_mappings:
            confidences = [m.confidence for m in tech_mappings]
            info = TechniqueCoverageInfo(
                technique_id=tech_id,
                technique_name=tech["name"],
                tactic_id=tech["tactic_id"],
                tactic_name=tech["tactic_name"],
                status="covered",
                detection_count=len(tech_mappings),
                max_confidence=max(confidences),
                avg_confidence=sum(confidences) / len(confidences),
            )
        else:
            info = TechniqueCoverageInfo(
                technique_id=tech_id,
                technique_name=tech["name"],
                tactic_id=tech["tactic_id"],
                tactic_name=tech["tactic_name"],
                status="uncovered",
                detection_count=0,
                max_confidence=0.0,
                avg_confidence=0.0,
            )
        coverage.append(info)

    return coverage


def calculate_tactic_summary(
    technique_coverage: list[TechniqueCoverageInfo],
) -> dict[str, dict]:
    """Calculate per-tactic coverage summary.

    Returns dict keyed by tactic_name with counts and percentage.
    """
    tactics: dict[str, dict] = {}

    for tc in technique_coverage:
        tactic = tc.tactic_name
        if tactic not in tactics:
            tactics[tactic] = {"total": 0, "covered": 0, "tactic_id": tc.tactic_id}
        tactics[tactic]["total"] += 1
        if tc.status == "covered":
            tactics[tactic]["covered"] += 1

    for tactic_data in tactics.values():
        total = tactic_data["total"]
        covered = tactic_data["covered"]
        tactic_data["percentage"] = round(
            (covered / total * 100) if total > 0 else 0, 1
        )

    return tactics


# ---------------------------------------------------------------------------
# MITRE technique retrieval (from Redis cache)
# ---------------------------------------------------------------------------


async def _get_all_techniques() -> list[dict]:
    """Retrieve all MITRE ATT&CK techniques (cache-first, DB fallback).

    Tries Redis cache first. On miss, queries the database directly
    and populates the cache for subsequent requests.
    """
    from app.core.cache import get_cached_techniques
    from app.core.database import get_db_session

    # Fast path: cache hit
    cache_key = f"{mitre_techniques_key()}:cloud=True"
    cached = await get_cached(cache_key)
    if cached:
        return cached

    # Slow path: cache miss — query DB and populate cache
    logger.info("quick_scan_mitre_cache_miss_falling_back_to_db")
    try:
        async with get_db_session() as db:
            return await get_cached_techniques(db, cloud_only=True)
    except Exception:
        logger.warning("quick_scan_mitre_db_fallback_failed", exc_info=True)
        return []


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------


async def run_quick_scan(content: str) -> dict:
    """Run a quick scan on Terraform HCL content.

    Flow:
    1. Parse HCL -> RawDetection objects
    2. Map RawDetections -> MappingResults (PatternMapper)
    3. Build technique coverage (standalone function)
    4. Analyse gaps (GapAnalyzer — no DB dependency)
    5. Return structured result

    Args:
        content: Raw Terraform HCL string (untrusted).

    Returns:
        Dict with coverage summary, technique details, and top gaps.
    """
    # Step 1: Parse
    parse_result: ParseResult = await parse_terraform_content(content)

    if not parse_result.detections:
        return _empty_result(parse_result)

    # Step 2: Map to MITRE techniques
    mapper = PatternMapper()
    all_mappings = []
    for rd in parse_result.detections:
        mappings = mapper.map_detection(rd)
        all_mappings.extend(mappings)

    # Step 3: Build coverage
    all_techniques = await _get_all_techniques()
    if not all_techniques:
        return _empty_result(parse_result, error="MITRE technique data unavailable")

    technique_coverage = build_technique_coverage_from_mappings(
        all_techniques, all_mappings
    )

    # Step 4: Gap analysis
    gap_analyzer = GapAnalyzer()
    gaps = gap_analyzer.analyze_gaps(technique_coverage, limit=10)

    # Step 5: Build response
    # Filter out pre-compromise tactics from coverage and summaries
    filtered_coverage = [
        tc for tc in technique_coverage if tc.tactic_id not in _PRE_COMPROMISE_TACTICS
    ]
    tactic_summary = calculate_tactic_summary(filtered_coverage)
    covered = sum(1 for tc in filtered_coverage if tc.status == "covered")
    total = len(filtered_coverage)

    return {
        "summary": {
            "total_techniques": total,
            "covered_techniques": covered,
            "coverage_percentage": round(
                (covered / total * 100) if total > 0 else 0, 1
            ),
            "detections_found": len(parse_result.detections),
            "resources_parsed": parse_result.resource_count,
            "truncated": parse_result.truncated,
        },
        "tactic_coverage": tactic_summary,
        "technique_coverage": [
            {
                "technique_id": tc.technique_id,
                "technique_name": tc.technique_name,
                "tactic_id": tc.tactic_id,
                "detection_count": tc.detection_count,
                "max_confidence": tc.max_confidence,
                "status": tc.status,
            }
            for tc in filtered_coverage
        ],
        "top_gaps": [
            {
                "technique_id": g.technique_id,
                "technique_name": g.technique_name,
                "tactic_name": g.tactic_name,
                "priority": g.priority,
            }
            for g in gaps
        ],
        "detections": [
            {
                "name": d.name,
                "detection_type": d.detection_type.value,
                "source_arn": d.source_arn,
            }
            for d in parse_result.detections[:50]  # Limit response size
        ],
    }


def _empty_result(parse_result: ParseResult, error: str | None = None) -> dict:
    """Return an empty result when no detections are found."""
    result = {
        "summary": {
            "total_techniques": 0,
            "covered_techniques": 0,
            "coverage_percentage": 0.0,
            "detections_found": 0,
            "resources_parsed": parse_result.resource_count,
            "truncated": False,
        },
        "tactic_coverage": {},
        "technique_coverage": [],
        "top_gaps": [],
        "detections": [],
    }
    if error:
        result["error"] = error
    return result
