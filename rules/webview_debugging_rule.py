# =============================================================================
# rules/webview_debugging_rule.py
# MASTG-BEST-0008 | MASTG-TEST-0227
# Category: PLATFORM | Severity: HIGH
# =============================================================================

import os
import re

# Unambiguous WebView debugging enablement
WEBVIEW_DEBUG_TRUE = re.compile(
    r'WebView\.setWebContentsDebuggingEnabled\s*\(\s*true\s*\)'
)

# Guard: presence of both of these indicates conditional (safe) usage
FLAG_DEBUGGABLE   = re.compile(r'ApplicationInfo\.FLAG_DEBUGGABLE')
GET_APP_FLAGS     = re.compile(r'getApplicationInfo\s*\(\s*\)\.flags')


def run(context):
    """
    MASTG-BEST-0008 — Debugging Disabled for WebViews.

    FAIL if setWebContentsDebuggingEnabled(true) is called unconditionally,
    i.e. without checking ApplicationInfo.FLAG_DEBUGGABLE first.

    PASS if the call is guarded by the debuggable-state check,
    or absent entirely.
    """
    sources_path = context.get("sources_path")

    if not sources_path or not os.path.isdir(sources_path):
        return (
            "PASS",
            "Java source not available for WebView debugging analysis",
            "MEDIUM",
            "MASTG-BEST-0008",
            "PLATFORM"
        )

    unguarded = []
    guarded   = []

    for dirpath, _, files in os.walk(sources_path):
        for fname in files:
            if not fname.endswith(".java"):
                continue
            try:
                with open(os.path.join(dirpath, fname), "r", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            if not WEBVIEW_DEBUG_TRUE.search(content):
                continue

            # If the file also checks FLAG_DEBUGGABLE via getApplicationInfo(),
            # the debug call is conditionally guarded — acceptable practice.
            if FLAG_DEBUGGABLE.search(content) and GET_APP_FLAGS.search(content):
                guarded.append(os.path.join(dirpath, fname))
            else:
                unguarded.append(os.path.join(dirpath, fname))

    if unguarded:
        return (
            "FAIL",
            {
                "unguarded_webview_debugging": unguarded,
                "guarded_webview_debugging":   guarded,
            },
            "HIGH",
            "MASTG-BEST-0008",
            "PLATFORM"
        )

    if guarded:
        return (
            "PASS",
            "WebView debugging enabled only within debuggable build checks",
            "MEDIUM",
            "MASTG-BEST-0008",
            "PLATFORM"
        )

    return (
        "PASS",
        "setWebContentsDebuggingEnabled(true) not found",
        "MEDIUM",
        "MASTG-BEST-0008",
        "PLATFORM"
    )
