import re
from urllib.parse import parse_qs, unquote, urlparse

import tool


def _first_query_value(query, *keys, default=""):
    """Return the first non-empty value for the first matching query key."""
    for key in keys:
        values = query.get(key)
        if values:
            return values[0]
    return default


def _parse_non_negative_int(value, field_name):
    """Parse a non-negative integer safely."""
    try:
        result = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Invalid {field_name}: {value!r}"
        ) from exc

    if result < 0:
        raise ValueError(
            f"Invalid {field_name}: {value!r}"
        )

    return result


def _parse_port(parsed):
    """Use urllib.parse's authority parser instead of manually splitting netloc."""
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(
            f"Invalid AnyTLS port: {exc}"
        ) from exc

    if port is None:
        raise ValueError("AnyTLS port is missing")

    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid AnyTLS port: {port}")

    return port


def _parse_server(parsed):
    """Return normalized hostname, including IPv6 without brackets."""
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("AnyTLS server is missing")

    return hostname


def _parse_password(parsed, query):
    """
    Prefer ?auth=... when present.
    Otherwise use URI userinfo password.
    """
    password = _first_query_value(query, "auth")

    if password == "":
        password = parsed.password or ""

    password = unquote(password)

    if password == "":
        raise ValueError("AnyTLS password is missing")

    return password


def parse(data):
    if not isinstance(data, str):
        raise ValueError("AnyTLS share link must be a string")

    info = data.strip()

    if not info:
        raise ValueError("Empty AnyTLS share link")

    parsed = urlparse(info)

    if parsed.scheme.lower() != "anytls":
        raise ValueError(
            f"Unsupported AnyTLS scheme: {parsed.scheme!r}"
        )

    server = _parse_server(parsed)
    server_port = _parse_port(parsed)

    query = parse_qs(
        parsed.query,
        keep_blank_values=True,
        strict_parsing=False,
    )

    password = _parse_password(parsed, query)

    tag = unquote(parsed.fragment)
    if not tag:
        tag = f"{tool.genName()}_anytls"

    node = {
        "tag": tag,
        "type": "anytls",
        "server": server,
        "server_port": server_port,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": _first_query_value(
                query,
                "sni",
                "peer",
                default="",
            ),
            "insecure": False,
        },
    }

    # Session options
    idle_check = _first_query_value(
        query,
        "idleSessionCheckInterval",
    )
    if idle_check != "":
        value = _parse_non_negative_int(
            idle_check,
            "idleSessionCheckInterval",
        )
        node["idle_session_check_interval"] = f"{value}s"

    idle_timeout = _first_query_value(
        query,
        "idleSessionTimeout",
    )
    if idle_timeout != "":
        value = _parse_non_negative_int(
            idle_timeout,
            "idleSessionTimeout",
        )
        node["idle_session_timeout"] = f"{value}s"

    min_idle = _first_query_value(
        query,
        "minIdleSession",
    )
    if min_idle != "":
        node["min_idle_session"] = _parse_non_negative_int(
            min_idle,
            "minIdleSession",
        )

    # uTLS fingerprint
    fingerprint = _first_query_value(
        query,
        "fp",
        "fingerprint",
    )
    if fingerprint:
        node["tls"]["utls"] = {
            "enabled": True,
            "fingerprint": fingerprint,
        }

    # ALPN
    alpn = _first_query_value(query, "alpn")
    if alpn:
        alpn = alpn.strip()

        # Some share-link generators emit {h2,http/1.1}
        if (
            len(alpn) >= 2
            and alpn.startswith("{")
            and alpn.endswith("}")
        ):
            alpn = alpn[1:-1]

        values = [
            item.strip()
            for item in alpn.split(",")
            if item.strip()
        ]

        if values:
            node["tls"]["alpn"] = values

    # TLS verification
    insecure = _first_query_value(
        query,
        "insecure",
        "allowInsecure",
        default="0",
    )

    if insecure.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        node["tls"]["insecure"] = True

    return node
