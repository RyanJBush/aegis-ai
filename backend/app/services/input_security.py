import ipaddress
from urllib.parse import urlparse

from fastapi import HTTPException, status

BLOCKED_HOSTS = {"localhost", "127.0.0.1", "::1"}


def validate_scan_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target must be HTTP/HTTPS URL")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target hostname is required")
    if hostname in BLOCKED_HOSTS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Localhost targets are not allowed")

    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Private IP targets are not allowed")
    except ValueError:
        # Not an IP literal; allow DNS hostnames.
        pass

    return target
