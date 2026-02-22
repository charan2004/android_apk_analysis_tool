# =============================================================================
# rules/webview_cache_cleanup_rule.py
# MASTG-BEST-0028 | MASTG-TEST-0320
# Category: PRIVACY | Severity: MEDIUM
# =============================================================================

import os
import re

# --- Storage enablement APIs ---
CACHE_ENABLED      = re.compile(r'setAppCacheEnabled\s*\(\s*true\s*\)')
DOM_STORAGE_ENABLED = re.compile(r'setDomStorageEnabled\s*\(\s*true\s*\)')
DB_ENABLED         = re.compile(r'setDatabaseEnabled\s*\(\s*true\s*\)')
COOKIE_ENABLED     = re.compile(r'setAcceptCookie\s*\(\s*true\s*\)')

# LOAD_NO_CACHE means WebView will not use a disk cache
CACHE_MODE_NONE    = re.compile(r'setCacheMode\s*\(\s*WebSettings\.LOAD_NO_CACHE\s*\)')

# --- Cleanup / disable APIs ---
CLEAR_CACHE        = re.compile(r'clearCache\s*\(\s*true\s*\)')
DELETE_WEBSTORAGE  = re.compile(r'WebStorage\.getInstance\s*\(\s*\)\.deleteAllData')
CLEAR_COOKIES      = re.compile(r'removeAllCookies\s*\(')


def run(context):
    """
    MASTG-BEST-0028 — WebView Cache Cleanup.

    FAIL if WebView storage (cache / DOM storage / database / cookies)
    is enabled without any corresponding cleanup mechanism.

    PASS if:
      - Storage is not enabled at all, OR
      - Cache mode is LOAD_NO_CACHE, OR
      - Appropriate cleanup APIs are present.

    NOTE: This is static analysis — runtime cleanup cannot be guaranteed.
    Dynamic analysis is recommended for confirmation.
    """
    sources_path = context.get("sources_path")

    if not sources_path or not os.path.isdir(sources_path):
        return (
            "PASS",
            "Java source not available for WebView cache analysis",
            "MEDIUM",
            "MASTG-BEST-0028",
            "PRIVACY"
        )

    storage_enabled = False
    cache_disabled  = False
    cleanup_present = False

    enabled_apis = []
    cleanup_apis = []

    for dirpath, _, files in os.walk(sources_path):
        for fname in files:
            if not fname.endswith(".java"):
                continue
            try:
                with open(os.path.join(dirpath, fname), "r", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            if CACHE_ENABLED.search(content):
                storage_enabled = True
                enabled_apis.append("setAppCacheEnabled(true)")

            if DOM_STORAGE_ENABLED.search(content):
                storage_enabled = True
                enabled_apis.append("setDomStorageEnabled(true)")

            if DB_ENABLED.search(content):
                storage_enabled = True
                enabled_apis.append("setDatabaseEnabled(true)")

            if COOKIE_ENABLED.search(content):
                storage_enabled = True
                enabled_apis.append("setAcceptCookie(true)")

            if CACHE_MODE_NONE.search(content):
                cache_disabled = True

            if CLEAR_CACHE.search(content):
                cleanup_present = True
                cleanup_apis.append("WebView.clearCache(true)")

            if DELETE_WEBSTORAGE.search(content):
                cleanup_present = True
                cleanup_apis.append("WebStorage.deleteAllData()")

            if CLEAR_COOKIES.search(content):
                cleanup_present = True
                cleanup_apis.append("CookieManager.removeAllCookies()")

    # ---- Storage enabled with no cache disable or cleanup API ----
    if storage_enabled and not cache_disabled and not cleanup_present:
        return (
            "FAIL",
            {
                "storage_enabled":  list(set(enabled_apis)),
                "cleanup_missing":  True,
            },
            "MEDIUM",
            "MASTG-BEST-0028",
            "PRIVACY"
        )

    if storage_enabled:
        return (
            "PASS",
            {
                "storage_enabled": list(set(enabled_apis)),
                "cleanup":         cleanup_apis or ["Cache disabled via LOAD_NO_CACHE"],
            },
            "MEDIUM",
            "MASTG-BEST-0028",
            "PRIVACY"
        )

    return (
        "PASS",
        "No WebView storage enablement detected",
        "MEDIUM",
        "MASTG-BEST-0028",
        "PRIVACY"
    )
