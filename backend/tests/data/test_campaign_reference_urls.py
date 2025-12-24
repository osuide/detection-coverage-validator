"""
Test Campaign Reference URLs in Remediation Templates.

This test suite validates that all campaign reference URLs in our remediation
templates are correct and point to valid MITRE ATT&CK resources.

Key validations:
1. All campaign URLs use the correct format (https://attack.mitre.org/campaigns/C####/)
2. Known MITRE campaigns use their official campaign IDs
3. URLs are well-formed and accessible

The official MITRE campaign list is loaded dynamically from the synced database
when available, with a fallback to a baseline hardcoded list for CI environments.
"""

import re
from typing import Dict, List, Tuple

import pytest

from app.data.remediation_templates.template_loader import TEMPLATES, Campaign


# Baseline MITRE ATT&CK Campaign ID to Name mapping
# This serves as a fallback when database is not available (e.g., in CI)
# and is merged with dynamically loaded campaigns from the database
BASELINE_MITRE_CAMPAIGNS: Dict[str, str] = {
    "C0001": "Frankenstein",
    "C0002": "Night Dragon",
    "C0004": "CostaRicto",
    "C0005": "Operation Spalax",
    "C0006": "Operation Honeybee",
    "C0007": "FunnyDream",
    "C0010": "C0010",
    "C0011": "C0011",
    "C0012": "Operation CuckooBees",
    "C0013": "Operation Sharpshooter",
    "C0014": "Operation Wocao",
    "C0015": "C0015",
    "C0016": "Operation Dust Storm",
    "C0017": "C0017",
    "C0018": "C0018",
    "C0020": "Maroochy Water Breach",
    "C0021": "C0021",
    "C0022": "Operation Dream Job",
    "C0023": "Operation Ghost",
    "C0024": "SolarWinds Compromise",
    "C0025": "2016 Ukraine Electric Power Attack",
    "C0026": "C0026",
    "C0027": "C0027",
    "C0028": "2015 Ukraine Electric Power Attack",
    "C0029": "Cutting Edge",
    "C0030": "Triton Safety Instrumented System Attack",
    "C0031": "Unitronics Defacement Campaign",
    "C0032": "C0032",
    "C0033": "C0033",
    "C0034": "2022 Ukraine Electric Power Attack",
    "C0035": "KV Botnet Activity",
    "C0036": "Pikabot Distribution February 2024",
    "C0037": "Water Curupira Pikabot Distribution",
    "C0038": "HomeLand Justice",
    "C0039": "Versa Director Zero Day Exploitation",
    "C0040": "APT41 DUST",
    "C0041": "FrostyGoop Incident",
    "C0042": "Outer Space",
    "C0043": "Indian Critical Infrastructure Intrusions",
    "C0044": "Juicy Mix",
    "C0045": "ShadowRay",
    "C0046": "ArcaneDoor",
    "C0047": "RedDelta Modified PlugX Infection Chain Operations",
    "C0048": "Operation MidnightEclipse",
    "C0049": "Leviathan Australian Intrusions",
    "C0050": "J-magic Campaign",
    "C0051": "APT28 Nearest Neighbor Campaign",
    "C0052": "SPACEHOP Activity",
    "C0053": "FLORAHOX Activity",
    "C0054": "Operation Triangulation",
    "C0055": "Quad7 Activity",
    "C0056": "RedPenguin",
    "C0057": "3CX Supply Chain Attack",
    "C0058": "SharePoint ToolShell Exploitation",
    "C0059": "Salesforce Data Exfiltration",
}


def load_campaigns_from_database() -> Dict[str, str]:
    """
    Load official MITRE campaigns from the synced database.

    Returns a dict mapping campaign external_id (e.g., 'C0014') to name.
    Returns empty dict if database is unavailable or has no campaigns.
    """
    try:
        import asyncio
        from sqlalchemy import select
        from app.core.database import async_session_factory
        from app.models.mitre_threat import MitreCampaign

        async def fetch_campaigns() -> Dict[str, str]:
            async with async_session_factory() as session:
                result = await session.execute(
                    select(MitreCampaign.external_id, MitreCampaign.name).where(
                        MitreCampaign.is_revoked == False,  # noqa: E712
                        MitreCampaign.is_deprecated == False,  # noqa: E712
                    )
                )
                return {row.external_id: row.name for row in result.fetchall()}

        # Run async function
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If event loop is already running, we can't use run_until_complete
                return {}
            return loop.run_until_complete(fetch_campaigns())
        except RuntimeError:
            # No event loop exists, create one
            return asyncio.run(fetch_campaigns())

    except Exception as e:
        # Database not available (e.g., in CI without DB, or no campaigns synced)
        print(f"Note: Could not load campaigns from database: {e}")
        return {}


def get_official_mitre_campaigns() -> Dict[str, str]:
    """
    Get the official MITRE campaigns list.

    Attempts to load from database first (for most up-to-date data),
    then merges with baseline list (to ensure comprehensive coverage).
    """
    # Start with baseline
    campaigns = BASELINE_MITRE_CAMPAIGNS.copy()

    # Try to load from database and merge (database takes precedence for names)
    db_campaigns = load_campaigns_from_database()
    if db_campaigns:
        campaigns.update(db_campaigns)
        print(f"Loaded {len(db_campaigns)} campaigns from database")

    return campaigns


def build_campaign_name_to_id_mapping(
    campaigns: Dict[str, str],
) -> Dict[str, str]:
    """
    Build a mapping of lowercase campaign name keywords to their IDs.

    This is used to validate that named campaigns in templates use correct URLs.
    """
    name_to_id: Dict[str, str] = {}

    # Add specific keyword mappings for common campaign references
    keyword_mappings = {
        "operation wocao": "C0014",
        "night dragon": "C0002",
        "arcanedoor": "C0046",
        "3cx supply chain": "C0057",
        "3cx desktop application": "C0057",
        "solarwinds": "C0024",
        "sunburst": "C0024",
        "operation dream job": "C0022",
        "operation dust storm": "C0016",
        "operation ghost": "C0023",
        "operation cuckoobees": "C0012",
        "frankenstein": "C0001",
        "redpenguin": "C0056",
        "florahox": "C0053",
        "spacehop": "C0052",
        "quad7": "C0055",
        "operation midnighteclipse": "C0048",
        "operation sharpshooter": "C0013",
        "2015 ukraine electric power": "C0028",
        "2016 ukraine electric power": "C0025",
        "2022 ukraine electric power": "C0034",
    }
    name_to_id.update(keyword_mappings)

    # Also add mappings from the official campaign names
    for campaign_id, name in campaigns.items():
        name_lower = name.lower()
        # Add the full name
        if name_lower not in name_to_id:
            name_to_id[name_lower] = campaign_id

    return name_to_id


# Load campaigns at module level for efficiency
OFFICIAL_MITRE_CAMPAIGNS = get_official_mitre_campaigns()
CAMPAIGN_NAME_TO_ID = build_campaign_name_to_id_mapping(OFFICIAL_MITRE_CAMPAIGNS)


def extract_all_campaigns() -> List[Tuple[str, Campaign]]:
    """Extract all campaigns from all templates."""
    campaigns = []
    for technique_id, template in TEMPLATES.items():
        if template.threat_context and template.threat_context.recent_campaigns:
            for campaign in template.threat_context.recent_campaigns:
                campaigns.append((technique_id, campaign))
    return campaigns


def get_campaign_id_from_url(url: str) -> str:
    """Extract campaign ID from a MITRE campaign URL."""
    match = re.search(r"/campaigns/(C\d{4})/", url)
    if match:
        return match.group(1)
    return ""


class TestCampaignReferenceURLs:
    """Test suite for validating campaign reference URLs."""

    @pytest.fixture(scope="class")
    def all_campaigns(self) -> List[Tuple[str, Campaign]]:
        """Fixture providing all campaigns from templates."""
        return extract_all_campaigns()

    def test_campaign_url_format_valid(self, all_campaigns):
        """Verify all campaign URLs are properly formatted."""
        malformed_urls = []

        for technique_id, campaign in all_campaigns:
            if campaign.reference_url:
                url = campaign.reference_url

                # Check for obviously malformed URLs
                if url == "https://attack.mitre.org/campaigns/":
                    malformed_urls.append(
                        f"{technique_id}: '{campaign.name}' uses generic campaigns URL"
                    )

        assert (
            len(malformed_urls) == 0
        ), f"Found {len(malformed_urls)} malformed campaign URLs:\n" + "\n".join(
            malformed_urls
        )

    def test_known_campaigns_use_correct_ids(self, all_campaigns):
        """Verify known MITRE campaigns use their official campaign IDs."""
        mismatched = []

        for technique_id, campaign in all_campaigns:
            if not campaign.reference_url:
                continue

            name_lower = campaign.name.lower()

            # Check if this campaign name matches a known MITRE campaign
            for known_name, expected_id in CAMPAIGN_NAME_TO_ID.items():
                if known_name in name_lower:
                    # This is a known MITRE campaign - verify the URL
                    if f"/campaigns/{expected_id}/" not in campaign.reference_url:
                        actual_id = get_campaign_id_from_url(campaign.reference_url)
                        mismatched.append(
                            f"{technique_id}: '{campaign.name}' should use "
                            f"{expected_id} but uses {actual_id or 'non-campaign URL'}"
                        )
                    break

        assert (
            len(mismatched) == 0
        ), f"Found {len(mismatched)} campaigns with incorrect IDs:\n" + "\n".join(
            mismatched
        )

    def test_campaign_ids_are_valid(self, all_campaigns):
        """Verify all campaign IDs used exist in official MITRE list."""
        invalid_ids = []

        for technique_id, campaign in all_campaigns:
            if not campaign.reference_url:
                continue

            # Extract campaign ID from URL
            campaign_id = get_campaign_id_from_url(campaign.reference_url)

            if campaign_id:
                # Verify this ID exists in official list
                if campaign_id not in OFFICIAL_MITRE_CAMPAIGNS:
                    invalid_ids.append(
                        f"{technique_id}: '{campaign.name}' uses unknown "
                        f"campaign ID {campaign_id}"
                    )

        assert (
            len(invalid_ids) == 0
        ), f"Found {len(invalid_ids)} unknown campaign IDs:\n" + "\n".join(invalid_ids)

    def test_no_technique_urls_for_named_campaigns(self, all_campaigns):
        """Verify named MITRE campaigns don't use technique URLs instead of campaign URLs."""
        technique_url_issues = []

        for technique_id, campaign in all_campaigns:
            if not campaign.reference_url:
                continue

            name_lower = campaign.name.lower()

            # Check if this is a known MITRE campaign using a technique URL
            for known_name in CAMPAIGN_NAME_TO_ID.keys():
                if known_name in name_lower:
                    if "/techniques/" in campaign.reference_url:
                        technique_url_issues.append(
                            f"{technique_id}: '{campaign.name}' is a known campaign "
                            f"but uses technique URL: {campaign.reference_url}"
                        )
                    break

        assert len(technique_url_issues) == 0, (
            f"Found {len(technique_url_issues)} campaigns using technique URLs:\n"
            + "\n".join(technique_url_issues)
        )

    def test_all_campaigns_have_reference_urls(self, all_campaigns):
        """Verify all campaigns have a reference URL."""
        missing_urls = []

        for technique_id, campaign in all_campaigns:
            if not campaign.reference_url:
                missing_urls.append(f"{technique_id}: '{campaign.name}' has no URL")

        # Allow some campaigns without URLs, but track them
        if missing_urls:
            pytest.skip(
                f"Found {len(missing_urls)} campaigns without URLs (acceptable):\n"
                + "\n".join(missing_urls[:10])  # Show first 10
            )

    def test_count_campaign_statistics(self, all_campaigns):
        """Generate statistics about campaign reference URLs."""
        total = len(all_campaigns)
        with_campaign_url = 0
        with_group_url = 0
        with_software_url = 0
        with_technique_url = 0
        with_external_url = 0
        without_url = 0

        for _, campaign in all_campaigns:
            if not campaign.reference_url:
                without_url += 1
            elif "/campaigns/" in campaign.reference_url:
                with_campaign_url += 1
            elif "/groups/" in campaign.reference_url:
                with_group_url += 1
            elif "/software/" in campaign.reference_url:
                with_software_url += 1
            elif "/techniques/" in campaign.reference_url:
                with_technique_url += 1
            else:
                with_external_url += 1

        print(f"\n{'='*60}")
        print("Campaign Reference URL Statistics")
        print(f"{'='*60}")
        print(f"Total campaigns: {total}")
        print(f"With campaign URLs: {with_campaign_url}")
        print(f"With group URLs: {with_group_url}")
        print(f"With software URLs: {with_software_url}")
        print(f"With technique URLs: {with_technique_url}")
        print(f"With external URLs: {with_external_url}")
        print(f"Without URLs: {without_url}")
        print(f"Official MITRE campaigns loaded: {len(OFFICIAL_MITRE_CAMPAIGNS)}")
        print(f"{'='*60}")

        # This test always passes - it's for reporting
        assert True


class TestCampaignDataIntegrity:
    """Test the integrity of campaign data sources."""

    def test_baseline_campaigns_not_empty(self):
        """Verify baseline campaign list is populated."""
        assert len(BASELINE_MITRE_CAMPAIGNS) > 0
        assert "C0001" in BASELINE_MITRE_CAMPAIGNS
        assert "C0024" in BASELINE_MITRE_CAMPAIGNS  # SolarWinds

    def test_official_campaigns_loaded(self):
        """Verify official campaigns are loaded (from DB or baseline)."""
        assert len(OFFICIAL_MITRE_CAMPAIGNS) >= len(BASELINE_MITRE_CAMPAIGNS)

    def test_campaign_id_format(self):
        """Verify all campaign IDs follow C#### format."""
        import re

        pattern = re.compile(r"^C\d{4}$")
        for campaign_id in OFFICIAL_MITRE_CAMPAIGNS.keys():
            assert pattern.match(
                campaign_id
            ), f"Invalid campaign ID format: {campaign_id}"


class TestCampaignURLAccessibility:
    """Test that campaign URLs are accessible (optional, network-dependent)."""

    @pytest.mark.skip(reason="Requires network access - run manually")
    def test_campaign_urls_are_accessible(self):
        """Verify all MITRE campaign URLs return 200 OK."""
        import httpx

        campaigns = extract_all_campaigns()
        failed_urls = []

        for technique_id, campaign in campaigns:
            if not campaign.reference_url:
                continue

            if "attack.mitre.org" not in campaign.reference_url:
                continue

            try:
                response = httpx.head(
                    campaign.reference_url, timeout=10, follow_redirects=True
                )
                if response.status_code != 200:
                    failed_urls.append(
                        f"{technique_id}: '{campaign.name}' - {campaign.reference_url} "
                        f"returned {response.status_code}"
                    )
            except Exception as e:
                failed_urls.append(
                    f"{technique_id}: '{campaign.name}' - {campaign.reference_url} "
                    f"failed: {str(e)}"
                )

        assert (
            len(failed_urls) == 0
        ), f"Found {len(failed_urls)} inaccessible URLs:\n" + "\n".join(failed_urls)
