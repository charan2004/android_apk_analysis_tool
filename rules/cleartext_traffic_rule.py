# =============================================================================
# rules/cleartext_traffic_rule.py
# MASTG-TEST-0235 — Android App Configurations Allowing Cleartext Traffic
# Category: NETWORK | Severity: HIGH
# =============================================================================

import xml.etree.ElementTree as ET
from mastg_scanner.utils.xml_utils import get_attr
from mastg_scanner.utils.fs_utils import find_xml_resource


def _parse_nsc_violations(nsc_path):
    """
    Parse network_security_config.xml and collect any elements where
    cleartextTrafficPermitted="true" is set in base-config or domain-config.

    Returns a list of violation strings.
    """
    violations = []
    try:
        tree = ET.parse(nsc_path)
        root = tree.getroot()
        for elem in root.iter():
            if elem.attrib.get("cleartextTrafficPermitted") == "true":
                tag = elem.tag.split("}")[-1]    # strip namespace if present
                violations.append(f'<{tag} cleartextTrafficPermitted="true">')
    except Exception as exc:
        violations.append(f"Error parsing network_security_config.xml: {exc}")
    return violations


def run(context):
    """
    MASTG-TEST-0235 — Cleartext Traffic Configuration.

    Checks:
      1. android:usesCleartextTraffic in <application>
      2. cleartextTrafficPermitted="true" in network_security_config.xml

    An NSC that prohibits cleartext overrides the manifest flag.
    """
    application = context.get("application")
    res_dir     = context.get("res_dir")

    uses_cleartext = get_attr(application, "usesCleartextTraffic") == "true"

    # Locate Network Security Config (XML resource)
    nsc_path = find_xml_resource(res_dir, "xml", "network_security_config.xml")

    # ---- Case 1: Manifest allows cleartext, no NSC to override ----
    if uses_cleartext and not nsc_path:
        return (
            "FAIL",
            'usesCleartextTraffic="true" with no Network Security Config',
            "HIGH",
            "MASTG-TEST-0235",
            "NETWORK"
        )

    # ---- Case 2: NSC present — check its contents ----
    if nsc_path:
        violations = _parse_nsc_violations(nsc_path)
        if violations:
            return (
                "FAIL",
                violations,
                "HIGH",
                "MASTG-TEST-0235",
                "NETWORK"
            )

        # NSC present and clean — manifest flag is overridden
        if uses_cleartext:
            return (
                "PASS",
                'usesCleartextTraffic="true" overridden by Network Security Config',
                "HIGH",
                "MASTG-TEST-0235",
                "NETWORK"
            )

    # ---- All clear ----
    return (
        "PASS",
        "Cleartext traffic not permitted",
        "HIGH",
        "MASTG-TEST-0235",
        "NETWORK"
    )
