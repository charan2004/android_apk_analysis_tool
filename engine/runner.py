# =============================================================================
# engine/runner.py — Rule orchestration
# =============================================================================

import traceback

from mastg_scanner.rules import (
    debuggable_flag_rule,
    backup_exclusion_rule,
    cleartext_traffic_rule,
    exported_components_rule,
    broken_symmetric_encryption_rule,
    notification_exposure_rule,
    webview_debugging_rule,
    webview_cache_cleanup_rule,
    webview_content_provider_rule,
    webview_local_file_access_rule,
)
from mastg_scanner.utils.manifest_utils import has_post_notifications_permission


# Ordered list of (display_name, rule_module) tuples.
# Adding a new rule is a one-liner here — no other file needs changing.
_RULES = [
    # --- Platform ---
    ("Debuggable Flag Disabled",                       debuggable_flag_rule),
    ("Exported Components Restricted",                 exported_components_rule),

    # --- Storage ---
    ("Exclude Sensitive Data from Backups",            backup_exclusion_rule),

    # --- Network ---
    ("Cleartext Traffic Configuration",               cleartext_traffic_rule),

    # --- Crypto ---
    ("Secure Encryption Modes (No ECB)",               broken_symmetric_encryption_rule),

    # --- Privacy ---
    ("Sensitive Data Exposure in Notifications",       notification_exposure_rule),
    ("WebView Cache Cleanup",                          webview_cache_cleanup_rule),

    # --- Platform / WebView ---
    ("WebView Debugging Disabled",                     webview_debugging_rule),
    ("Disable Content Provider Access in WebViews",    webview_content_provider_rule),
    ("Securely Load File Content in WebViews",         webview_local_file_access_rule),
]


def run_all(context):
    """
    Execute every registered rule against the provided context dict.

    Context keys expected:
        xml_root                  – parsed AndroidManifest ET root
        application               – <application> ET element
        package_name              – app package name string
        sources_path              – path to .java sources directory (or None)
        res_dir                   – path to res/ directory (or None)
        min_sdk                   – int or None
        post_notifications_declared – bool

    Returns:
        List of (rule_name, (status, evidence, severity, mastg_id, category))
    """
    # Enrich context with computed values needed by multiple rules
    enriched = dict(context)
    enriched.setdefault(
        "post_notifications_declared",
        has_post_notifications_permission(context["xml_root"])
    )

    results = []
    for name, module in _RULES:
        try:
            result = module.run(enriched)
            results.append((name, result))
        except Exception as exc:
            # Never let a single rule crash the entire scan
            results.append((
                name,
                (
                    "ERROR",
                    f"Rule raised an exception: {exc}\n{traceback.format_exc()}",
                    "HIGH",
                    "N/A",
                    "UNKNOWN"
                )
            ))

    return results
