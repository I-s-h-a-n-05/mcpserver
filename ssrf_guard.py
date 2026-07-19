"""
SSRF guard. Any registered_apis.url_template gets sent a real outbound HTTP
request by execution_proxy.execute(), with the host coming from a DB row
that an admin (or, pre-auth-fix, anyone) can write. Without this check the
gateway is a general-purpose SSRF relay: register a "tool" pointed at
169.254.169.254 (cloud metadata), localhost, or an internal service, and
any agent that can call the tool gets a proxied response back.

Called twice, deliberately:
  1. At registration time (registry.create_api / main.py /admin/apis) --
     reject obviously bad URLs before they ever land in the DB.
  2. At execution time (execution_proxy.execute), on the fully-resolved
     URL -- because DNS is not stable between registration and call time
     (DNS rebinding: a hostname can resolve to a public IP when registered
     and to 127.0.0.1 or a link-local address when actually requested).
     Step 2 is the one that actually matters for security; step 1 is a
     fast-fail convenience for admins.
"""

import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}

# Hostnames that are never valid regardless of what they resolve to.
BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal"}


class SsrfBlockedError(Exception):
    """Raised when a URL resolves to (or names) a disallowed destination."""


def _is_blocked_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        # AWS/GCP/Azure metadata endpoint
        or str(ip) == "169.254.169.254"
    )


def validate_url_syntax(url: str) -> None:
    """
    Cheap, DNS-free checks. Run at registration time so bad templates are
    rejected immediately with a clear error instead of failing later at
    call time. Does NOT guarantee safety at execution time -- see module
    docstring re: DNS rebinding.
    """
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise SsrfBlockedError(f"URL scheme must be http or https, got: {parts.scheme!r}")
    if not parts.hostname:
        raise SsrfBlockedError("URL has no hostname")
    if parts.hostname.lower() in BLOCKED_HOSTNAMES:
        raise SsrfBlockedError(f"Hostname is not allowed: {parts.hostname}")
    try:
        ip = ipaddress.ip_address(parts.hostname)
    except ValueError:
        return  # it's a DNS name, not an IP literal -- checked again at call time
    if _is_blocked_ip(str(ip)):
        raise SsrfBlockedError(f"URL resolves to a blocked IP range: {ip}")


def validate_url_resolved(url: str) -> None:
    """
    Resolve the hostname and check every returned address. Run this
    immediately before every outbound request in execution_proxy -- not
    just once at registration -- to close the DNS-rebinding gap (a name
    that pointed at a public IP when registered can be repointed at
    169.254.169.254 or 127.0.0.1 by the time the request actually fires).
    """
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise SsrfBlockedError(f"URL scheme must be http or https, got: {parts.scheme!r}")
    if not parts.hostname:
        raise SsrfBlockedError("URL has no hostname")
    if parts.hostname.lower() in BLOCKED_HOSTNAMES:
        raise SsrfBlockedError(f"Hostname is not allowed: {parts.hostname}")

    try:
        addr_infos = socket.getaddrinfo(parts.hostname, None)
    except socket.gaierror as e:
        raise SsrfBlockedError(f"Could not resolve host: {parts.hostname} ({e})") from e

    for family, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        if _is_blocked_ip(ip_str):
            raise SsrfBlockedError(
                f"Host {parts.hostname} resolves to a blocked address: {ip_str}"
            )
