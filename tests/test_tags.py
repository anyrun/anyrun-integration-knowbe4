import pytest

from exceptions import ObjectIsNone
from tags import Tags


class TestTagQuery:
    def test_wraps_tag_name(self):
        assert Tags.tag_query("ANYRUN_REQUEST") == 'tags:"ANYRUN_REQUEST"'


class TestInternalExclusionsQuery:
    def test_excludes_all_internal_tags_and_resolved_status(self):
        query = Tags.internal_exclusions_query()

        for tag in Tags.internal_exclusion_tags:
            assert f'-tags:"{tag}"' in query
        assert '-status:"Resolved"' in query


class TestBuildDiscoveryQuery:
    def test_default_ingestion_tag_only(self):
        query = Tags.build_discovery_query("", "ANYRUN_REQUEST")

        assert '(tags:"ANYRUN_REQUEST")' in query
        assert query.count(" AND (") == 1  # only the internal-exclusions clause + tag

    def test_combines_customer_filter_and_ingestion_tag(self):
        query = Tags.build_discovery_query('subject:"invoice"', "ANYRUN_REQUEST")

        assert '(tags:"ANYRUN_REQUEST")' in query
        assert '(subject:"invoice")' in query
        # ingestion tag clause must come before the customer filter clause
        assert query.index('tags:"ANYRUN_REQUEST"') < query.index('subject:"invoice"')

    def test_empty_ingestion_tag_means_ingest_everything(self):
        query = Tags.build_discovery_query("", "")

        assert "tags:" not in query.replace(
            "-tags:", ""
        )  # only the negative internal-exclusion tags remain
        assert '-status:"Resolved"' in query

    def test_ingestion_tag_is_stripped(self):
        query = Tags.build_discovery_query("", "  ANYRUN_REQUEST  ")
        assert '(tags:"ANYRUN_REQUEST")' in query


class TestNormalizeVerdict:
    def test_normalizes_case_spaces_and_hyphens(self):
        assert Tags.normalize_verdict("No Specific-Threat") == "no_specific_threat"

    def test_raises_on_none(self):
        with pytest.raises(ObjectIsNone):
            Tags.normalize_verdict(None)

    def test_raises_on_blank(self):
        with pytest.raises(ObjectIsNone):
            Tags.normalize_verdict("   ")


class TestMapVerdictToTag:
    @pytest.mark.parametrize(
        "verdict",
        ["Malicious activity", "malicious", "MALICIOUS-ACTIVITY"],
    )
    def test_malicious_variants(self, verdict):
        assert Tags.map_verdict_to_tag(verdict) == Tags.anyrun_malicious

    @pytest.mark.parametrize(
        "verdict",
        ["Suspicious activity", "suspicious"],
    )
    def test_suspicious_variants(self, verdict):
        assert Tags.map_verdict_to_tag(verdict) == Tags.anyrun_suspicious

    @pytest.mark.parametrize(
        "verdict",
        ["No threats detected", "clean", "benign", "no specific threat"],
    )
    def test_no_threat_variants(self, verdict):
        assert Tags.map_verdict_to_tag(verdict) == Tags.anyrun_no_specific_threat

    def test_unknown_verdict_defaults_to_no_specific_threat(self):
        assert (
            Tags.map_verdict_to_tag("something ANY.RUN never returns")
            == Tags.anyrun_no_specific_threat
        )
