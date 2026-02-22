# =============================================================================
# utils/xml_utils.py — Android XML namespace helper
# =============================================================================

from mastg_scanner.config import ANDROID_NS


def get_attr(element, attr_name):
    """
    Read an android:* attribute from an XML element.

    Args:
        element:   xml.etree.ElementTree.Element (e.g. <application>)
        attr_name: attribute local name without namespace prefix
                   e.g. "debuggable", "exported", "allowBackup"

    Returns:
        Attribute value string, or None if not present.
    """
    if element is None:
        return None
    return element.attrib.get(ANDROID_NS + attr_name)
