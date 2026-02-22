# =============================================================================
# config.py — Global constants for the MASTG Generic Scanner
# =============================================================================

# Android XML namespace used in AndroidManifest.xml and resource files
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Severity levels (ordered by risk)
SEVERITY_ORDER = ["HIGH", "MEDIUM", "LOW", "INFO"]

# Severity weights used for overall score calculation
SEVERITY_WEIGHT = {
    "HIGH":   3,
    "MEDIUM": 2,
    "LOW":    1,
    "INFO":   0,
}

# Display order for category summary output
CATEGORY_ORDER = [
    "PLATFORM",
    "STORAGE",
    "NETWORK",
    "CRYPTO",
    "PRIVACY",
]

# Tool banner
TOOL_NAME = "OWASP MASTG Generic Android Static Analyzer"
TOOL_VERSION = "1.0.0"
