# =============================================================================
# rules/exported_components_rule.py
# MASTG — Platform Interaction Security
# Category: PLATFORM | Severity: HIGH
# =============================================================================

from mastg_scanner.utils.xml_utils import get_attr


def run(context):
    """
    Check for over-exported Android components (activity, service, receiver).

    Classification:
      - first_party: component name starts with the app's package name
      - third_party: all others (SDKs, libraries)

    FAIL if first-party components are exported without restriction.
    PASS with warning evidence if only third-party components are exported.
    """
    xml_root     = context.get("xml_root")
    package_name = context.get("package_name", "")

    first_party  = []
    third_party  = []

    for tag in ["activity", "service", "receiver", "provider"]:
        for comp in xml_root.findall(f".//{tag}"):
            exported = get_attr(comp, "exported")
            name     = get_attr(comp, "name") or ""

            if exported != "true":
                continue

            # Classify: if the component name starts with the package it is
            # first-party; everything else is a library / SDK component.
            if package_name and (
                name.startswith(package_name)
                or name.startswith(f".{package_name}")
            ):
                first_party.append(f"<{tag}> {name}")
            else:
                third_party.append(f"<{tag}> {name}")

    if first_party:
        return (
            "FAIL",
            {
                "first_party_exported": first_party,
                "third_party_exported": third_party,
            },
            "HIGH",
            "MASTG-PLATFORM-0001",
            "PLATFORM"
        )

    return (
        "PASS",
        {
            "first_party_exported": [],
            "third_party_exported": third_party,
        },
        "HIGH",
        "MASTG-PLATFORM-0001",
        "PLATFORM"
    )
