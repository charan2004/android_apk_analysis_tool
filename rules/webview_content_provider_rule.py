# =============================================================================
# rules/webview_content_provider_rule.py
# MASTG-BEST-0013 | MASTG-TEST-0250
# Category: PLATFORM | Severity: HIGH
# =============================================================================

import os
import re

WEBVIEW_USAGE        = re.compile(r'\bWebView\b')

JS_ENABLED_TRUE      = re.compile(r'setJavaScriptEnabled\s*\(\s*true\s*\)')
JS_DISABLED          = re.compile(r'setJavaScriptEnabled\s*\(\s*false\s*\)')

CONTENT_ACCESS_TRUE  = re.compile(r'setAllowContentAccess\s*\(\s*true\s*\)')
CONTENT_ACCESS_FALSE = re.compile(r'setAllowContentAccess\s*\(\s*false\s*\)')

UNIVERSAL_TRUE       = re.compile(r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)')
UNIVERSAL_FALSE      = re.compile(r'setAllowUniversalAccessFromFileURLs\s*\(\s*false\s*\)')


def run(context):
    """
    MASTG-BEST-0013 — Disable Content Provider Access in WebViews.

    FAIL if all of the following are true in a single file:
      - JavaScript is enabled
      - Content provider access is enabled (explicit true OR not disabled)
      - Universal file URL access is enabled

    PASS if any mitigating control is present.
    """
    sources_path = context.get("sources_path")

    if not sources_path or not os.path.isdir(sources_path):
        return (
            "PASS",
            "Java source not available for WebView content provider analysis",
            "MEDIUM",
            "MASTG-BEST-0013",
            "PLATFORM"
        )

    risky_files = []
    safe_files  = []

    for dirpath, _, files in os.walk(sources_path):
        for fname in files:
            if not fname.endswith(".java"):
                continue
            try:
                with open(os.path.join(dirpath, fname), "r", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            if not WEBVIEW_USAGE.search(content):
                continue

            fpath = os.path.join(dirpath, fname)

            js_on      = JS_ENABLED_TRUE.search(content)
            js_off     = JS_DISABLED.search(content)
            ca_on      = CONTENT_ACCESS_TRUE.search(content)
            ca_off     = CONTENT_ACCESS_FALSE.search(content)
            univ_on    = UNIVERSAL_TRUE.search(content)
            univ_off   = UNIVERSAL_FALSE.search(content)

            # Any of these mitigations make the file safe
            if js_off or ca_off or univ_off:
                safe_files.append(fpath)
                continue

            # All three risky conditions must be present to FAIL
            if js_on and univ_on and not ca_off:
                risky_files.append(fpath)

    if risky_files:
        return (
            "FAIL",
            {"unsafe_webview_content_provider_config": risky_files},
            "HIGH",
            "MASTG-BEST-0013",
            "PLATFORM"
        )

    if safe_files:
        return (
            "PASS",
            "WebView content provider access restricted in all analyzed files",
            "MEDIUM",
            "MASTG-BEST-0013",
            "PLATFORM"
        )

    return (
        "PASS",
        "No risky WebView content provider configuration detected",
        "MEDIUM",
        "MASTG-BEST-0013",
        "PLATFORM"
    )
