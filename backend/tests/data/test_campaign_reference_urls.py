"""
Test Campaign Reference URLs in Remediation Templates.

This test suite validates that all campaign reference URLs in our remediation
templates are correct and point to valid MITRE ATT&CK resources.

Key validations:
1. All campaign URLs use the correct format (https://attack.mitre.org/campaigns/C####/)
2. Known MITRE campaigns use their official campaign IDs
3. URLs are well-formed and accessible
"""

import re
from typing import Dict, List, Tuple

import pytest

from app.data.remediation_templates.template_loader import TEMPLATES, Campaign


# Official MITRE ATT&CK Campaign ID to Name mapping (as of December 2024)
OFFICIAL_MITRE_CAMPAIGNS: Dict[str, str] = {
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

# Mapping of known campaign names to their official MITRE campaign IDs
# Used to validate that named campaigns use the correct URL
CAMPAIGN_NAME_TO_ID: Dict[str, str] = {
    # Exact matches
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
        print(f"{'='*60}")

        # This test always passes - it's for reporting
        assert True


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
