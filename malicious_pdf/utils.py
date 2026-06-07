import ipaddress

import validators


KNOWN_SCHEMES = (
    "http://", "https://", "ftp://", "ftps://", "file://", "smb://",
    "ssh://", "telnet://", "gopher://", "ldap://", "mailto:", "news:",
    "nntp://", "irc://", "data:", "javascript:",
)


def validate_url_or_ip_validators(input_string):
    """Validates if input is an IP address or a URL with a scheme."""
    try:
        ipaddress.ip_address(input_string)
        return True
    except ValueError:
        pass

    if validators.url(input_string):
        return True

    for scheme in KNOWN_SCHEMES:
        if input_string.lower().startswith(scheme) and len(input_string) > len(scheme):
            return True

    return False


def ensure_scheme(host):
    """Add https:// if the host has no recognized scheme (e.g. bare IP address)."""
    if not host.lower().startswith(KNOWN_SCHEMES):
        return f"https://{host}"
    return host
