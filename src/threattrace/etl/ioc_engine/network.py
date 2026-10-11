from __future__ import annotations

import ipaddress
from typing import Any

from threattrace.common.collections import dedupe_strings_lower_sorted as _dedupe
from threattrace.etl.ioc_engine.observability import (
    normalize_domain as _shared_normalize_domain,
)
from threattrace.etl.ioc_engine.observability import (
    normalize_ip as _shared_normalize_ip,
)
from threattrace.etl.ioc_engine.observability import (
    normalize_url as _shared_normalize_url,
)


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_link_local
        )
    except ValueError:
        return False


BENIGN_DOMAIN_KEYWORDS = (
    "microsoft",
    "azure",
    "office",
    "windows",
    "google",
    "gstatic",
    "cloudflare",
    "onenote",
    "live.com",
    "office365",
    "sharepoint",
    "m365",
)

SUSPICIOUS_TLDS = (
    ".biz",
    ".top",
    ".xyz",
    ".ru",
    ".cn",
    ".su",
    ".onion",
)

SUSPICIOUS_PORTS = {4444, 1337, 6666, 6667, 9001, 8081}


def _high_entropy_domain(domain: str) -> bool:
    # crude heuristic: many consonants / random-looking
    return len(domain) > 20 and sum(c.isdigit() for c in domain) > 3


def _normalize_domain(value: str) -> str | None:
    if not value:
        return None

    value = value.strip().lower()

    return _shared_normalize_domain(value)


def _normalize_ip(value: str) -> str | None:
    return _shared_normalize_ip(value, public_only=True)


def _is_benign_domain(domain: str) -> bool:
    return any(keyword in domain for keyword in BENIGN_DOMAIN_KEYWORDS)


def _is_suspicious_domain(domain: str) -> bool:
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return True

    if not _is_benign_domain(domain):
        return True

    return False


def _extract_host_like(entry: dict[str, Any]) -> tuple[list[str], list[str]]:
    domains: list[str] = []
    ips: list[str] = []

    for field in (
        "domain",
        "host",
        "hostname",
        "server",
        "request",
        "mailserver",
        "dst",
        "src",
        "ip",
        "address",
    ):
        raw = entry.get(field)
        if not isinstance(raw, str):
            continue

        normalized_domain = _normalize_domain(raw)
        if normalized_domain:
            domains.append(normalized_domain)
            continue

        normalized_ip = _normalize_ip(raw)
        if normalized_ip:
            ips.append(normalized_ip)

    return domains, ips


def extract_network_iocs(report: dict[str, Any]) -> dict[str, Any]:
    """
    Extract normalized network-based IoCs from CAPE report.

    Coverage:
    - Domains
    - IPs
    - URLs
    - DNS requests
    - HTTP hosts
    - TCP/UDP/ICMP connections
    - Public IP filtering
    """

    network = report.get("network", {}) or {}

    domains: list[str] = []
    ips: list[str] = []
    private_ips: list[str] = []
    urls: list[str] = []
    tls_sni: list[str] = []
    suspicious_domains: list[str] = []
    benign_domains: list[str] = []
    suspicious_connections: list[str] = []

    # Domains section
    for entry in network.get("domains", []) or []:
        domain = entry.get("domain")
        normalized_domain = _normalize_domain(domain)
        if normalized_domain:
            domains.append(normalized_domain)
            if _is_suspicious_domain(normalized_domain):
                suspicious_domains.append(normalized_domain)
            else:
                benign_domains.append(normalized_domain)
            if _high_entropy_domain(normalized_domain):
                suspicious_domains.append(normalized_domain)

    # DNS requests
    for dns in network.get("dns", []) or []:
        request = dns.get("request")
        normalized_domain = _normalize_domain(request)
        if normalized_domain:
            domains.append(normalized_domain)
            if _is_suspicious_domain(normalized_domain):
                suspicious_domains.append(normalized_domain)
            else:
                benign_domains.append(normalized_domain)
            if _high_entropy_domain(normalized_domain):
                suspicious_domains.append(normalized_domain)

        for answer in dns.get("answers", []) or []:
            ip = answer.get("data")
            normalized_ip = _shared_normalize_ip(ip)
            if normalized_ip:
                if _is_public_ip(normalized_ip):
                    ips.append(normalized_ip)
                else:
                    private_ips.append(normalized_ip)

    # HTTP/HTTPS requests
    for http in network.get("http", []) or []:
        uri = http.get("uri")
        host = http.get("host")

        if uri:
            normalized_url = _shared_normalize_url(uri)
            if normalized_url:
                urls.append(normalized_url)
            parsed = _normalize_domain(uri)
            if parsed:
                domains.append(parsed)
                if _is_suspicious_domain(parsed):
                    suspicious_domains.append(parsed)
                else:
                    benign_domains.append(parsed)
                if _high_entropy_domain(parsed):
                    suspicious_domains.append(parsed)

        if host:
            normalized_domain = _normalize_domain(host)
            if normalized_domain:
                domains.append(normalized_domain)
                if _is_suspicious_domain(normalized_domain):
                    suspicious_domains.append(normalized_domain)
                else:
                    benign_domains.append(normalized_domain)
                if _high_entropy_domain(normalized_domain):
                    suspicious_domains.append(normalized_domain)
            if uri and isinstance(uri, str) and uri.startswith("/"):
                normalized_url = _shared_normalize_url(f"http://{host}{uri}")
                if normalized_url:
                    urls.append(normalized_url)

    # Generic connection protocols
    for protocol in ("tcp", "udp", "icmp"):
        for entry in network.get(protocol, []) or []:
            for field in ("dst", "src"):
                value = entry.get(field)
                normalized_ip = _shared_normalize_ip(value)
                if normalized_ip:
                    if _is_public_ip(normalized_ip):
                        ips.append(normalized_ip)
                    else:
                        private_ips.append(normalized_ip)

                    port = entry.get("dport") or entry.get("sport")
                    try:
                        port_int = int(port)
                    except (TypeError, ValueError):
                        port_int = None
                    if port_int in SUSPICIOUS_PORTS:
                        suspicious_connections.append(f"{normalized_ip}:{port}")

    for protocol in ("smtp", "irc"):
        for entry in network.get(protocol, []) or []:
            if not isinstance(entry, dict):
                continue
            protocol_domains, protocol_ips = _extract_host_like(entry)
            domains.extend(protocol_domains)
            ips.extend(protocol_ips)
            for value in protocol_domains:
                if _is_suspicious_domain(value):
                    suspicious_domains.append(value)
                else:
                    benign_domains.append(value)
                if _high_entropy_domain(value):
                    suspicious_domains.append(value)

    # Hosts
    for host in network.get("hosts", []) or []:
        ip = host.get("ip")
        normalized_ip = _shared_normalize_ip(ip)
        if normalized_ip:
            if _is_public_ip(normalized_ip):
                ips.append(normalized_ip)
            else:
                private_ips.append(normalized_ip)

    # TLS/SNI style sections vary across CAPE versions and network backends.
    for section in ("tls", "ssl", "https"):
        for entry in network.get(section, []) or []:
            if not isinstance(entry, dict):
                continue
            for field in ("sni", "server_name", "hostname", "host"):
                normalized_domain = _normalize_domain(entry.get(field))
                if normalized_domain:
                    tls_sni.append(normalized_domain)
                    domains.append(normalized_domain)
                    if _is_suspicious_domain(normalized_domain):
                        suspicious_domains.append(normalized_domain)

    domains_d = _dedupe(domains)
    ips_d = _dedupe(ips)
    private_ips_d = _dedupe(private_ips)
    urls_d = _dedupe(urls)
    tls_sni_d = _dedupe(tls_sni)
    suspicious_d = _dedupe(suspicious_domains)
    benign_d = _dedupe(benign_domains)
    connections_d = _dedupe(suspicious_connections)
    network_indicators = _dedupe(suspicious_d + ips_d + urls_d + connections_d)

    return {
        "domains": domains_d,
        "ips": ips_d,
        "private_ips": private_ips_d,
        "urls": urls_d,
        "tls_sni": tls_sni_d,
        "suspicious_domains": suspicious_d,
        "benign_domains": benign_d,
        "suspicious_connections": connections_d,
        "network_indicators": network_indicators,
        "counts": {
            "domains": len(domains_d),
            "ips": len(ips_d),
            "private_ips": len(private_ips_d),
            "urls": len(urls_d),
            "tls_sni": len(tls_sni_d),
            "suspicious_domains": len(suspicious_d),
            "benign_domains": len(benign_d),
            "suspicious_connections": len(connections_d),
            "network_indicators": len(network_indicators),
        },
    }
