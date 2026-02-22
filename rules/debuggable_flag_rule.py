# =============================================================================
# rules/debuggable_flag_rule.py
# MASTG-BEST-0007 | MASTG-TEST-0226
# Category: PLATFORM | Severity: MEDIUM
# =============================================================================

from mastg_scanner.utils.xml_utils import get_attr


def run(context):
    """
    Check that android:debuggable is NOT set to true in <application>.

    Absence of the attribute is secure — Android defaults to false in
    release builds. Only an explicit "true" value constitutes a failure.
    """
    application = context.get("application")
    debuggable = get_attr(application, "debuggable")

    if debuggable == "true":
        return (
            "FAIL",
            'android:debuggable="true" found in <application>',
            "MEDIUM",
            "MASTG-BEST-0007",
            "PLATFORM"
        )

    evidence = (
        'android:debuggable="false"'
        if debuggable == "false"
        else "android:debuggable not set (defaults to false in release builds)"
    )
    return (
        "PASS",
        evidence,
        "MEDIUM",
        "MASTG-BEST-0007",
        "PLATFORM"
    )
