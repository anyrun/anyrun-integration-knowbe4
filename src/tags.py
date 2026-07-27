from typing import Dict, List

from exceptions import ObjectIsNone


class Tags:
    anyrun_prefix: str = "ANYRUN_"

    anyrun_queued: str = "ANYRUN_QUEUED"
    anyrun_pending: str = "ANYRUN_PENDING"
    anyrun_scanned: str = "ANYRUN_SCANNED"
    anyrun_error: str = "ANYRUN_ERROR"
    anyrun_timeout: str = "ANYRUN_TIMEOUT"

    anyrun_malicious: str = "ANYRUN_MALICIOUS"
    anyrun_suspicious: str = "ANYRUN_SUSPICIOUS"
    anyrun_no_specific_threat: str = "ANYRUN_NO_SPECIFIC_THREAT"

    internal_exclusion_tags: List[str] = [
        anyrun_scanned,
        anyrun_pending,
        anyrun_queued,
        anyrun_error,
        anyrun_timeout,
    ]

    final_result_tags: Dict[str, str] = {
        "malicious": anyrun_malicious,
        "malicious_activity": anyrun_malicious,
        "suspicious": anyrun_suspicious,
        "suspicious_activity": anyrun_suspicious,
        "clean": anyrun_no_specific_threat,
        "no_specific_threat": anyrun_no_specific_threat,
        "no_threat": anyrun_no_specific_threat,
        "unknown": anyrun_no_specific_threat,
    }

    no_threat_tokens: List[str] = [
        "no_specific_threat",
        "no_threat",
        "clean",
        "benign",
        "safe",
        "no_malicious",
        "not_malicious",
        "undetected",
    ]

    @staticmethod
    def internal_exclusions_query() -> str:
        tag_exclusions = " AND ".join(
            f'-tags:"{tag}"' for tag in Tags.internal_exclusion_tags
        )

        return f'{tag_exclusions} AND -status:"Resolved"'

    @staticmethod
    def build_discovery_query(customer_filter: str = "", ingestion_tag: str = "") -> str:
        clauses = [Tags.internal_exclusions_query()]

        normalized_tag = ingestion_tag.strip()
        if normalized_tag:
            clauses.append(Tags.tag_query(normalized_tag))

        normalized_filter = customer_filter.strip()
        if normalized_filter:
            clauses.append(normalized_filter)

        return " AND ".join(f"({clause})" for clause in clauses)

    @staticmethod
    def tag_query(tag: str) -> str:
        return f'tags:"{tag}"'

    @staticmethod
    def normalize_verdict(verdict: str | None = None) -> str:
        if verdict is None:
            raise ObjectIsNone("`verdict` arg is None")

        verdict = verdict.strip().lower()

        if len(verdict) == 0:
            raise ObjectIsNone("`verdict` is empty after pre-normalizing")

        verdict = verdict.replace("-", "_").replace(" ", "_")

        return verdict

    @staticmethod
    def map_verdict_to_tag(verdict: str | None = None) -> str:
        value = Tags.normalize_verdict(verdict)

        if "malicious" in value:
            return Tags.anyrun_malicious
        if "suspicious" in value:
            return Tags.anyrun_suspicious

        for token in Tags.no_threat_tokens:
            if token in value:
                return Tags.anyrun_no_specific_threat

        return Tags.final_result_tags.get(value, Tags.anyrun_no_specific_threat)
