import tool
import re
from urllib.parse import urlparse, parse_qs, unquote


# ============================================================
# VLESS -> sing-box parser
#
# Target:
#   Official sing-box Android / Google Play 1.14.0
#
# Important:
#   Official upstream sing-box did NOT have XHTTP in the normal
#   upstream build at the time this parser was written.
#   Therefore XHTTP is NOT silently converted to HTTP.
#
#   If a future/third-party core explicitly supports:
#       "transport": {"type": "xhttp", ...}
#   set ENABLE_XHTTP = True.
# ============================================================

ENABLE_XHTTP = False


def _value(query, key, default=None):
    """Return a normalized scalar value from parse_qs output."""
    value = query.get(key, default)
    if isinstance(value, list):
        return value[0] if value else default
    return value


def _clean(value):
    if value is None:
        return None
    value = str(value).strip()
    if value.lower() in ("", "none", "null"):
        return None
    return value


def _as_list(value):
    """Parse comma/pipe separated values, preserving an existing list."""
    if value is None:
        return None
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    value = str(value)
    return [x.strip() for x in re.split(r"[,|]", value) if x.strip()]


def _parse_server(netloc):
    """
    Parse:
        uuid@host:port
        uuid@[IPv6]:port

    Return (uuid, server, port), or None.
    """
    if "@" not in netloc:
        return None

    uuid, address = netloc.rsplit("@", 1)
    uuid = uuid.strip()
    if not uuid:
        return None

    address = address.strip()

    # [IPv6]:port
    if address.startswith("["):
        match = re.match(r"^\[([^\]]+)\]:(\d+)$", address)
        if not match:
            return None
        server = match.group(1)
        server_port = int(match.group(2))
    else:
        # Normal hostname/IPv4:port
        match = re.match(r"^(.+):(\d+)$", address)
        if not match:
            return None
        server = match.group(1)
        server_port = int(match.group(2))

    if not 1 <= server_port <= 65535:
        return None

    return uuid, server, server_port


def _add_packet_encoding(node, query):
    packet_encoding = (_clean(_value(query, "packetEncoding")) or "").lower()
    if not packet_encoding:
        return True
    if packet_encoding in ("none", "disabled"):
        node["packet_encoding"] = ""
        return True
    if packet_encoding in ("xudp", "packetaddr"):
        node["packet_encoding"] = packet_encoding
        return True
    return False


def _add_flow(node, query):
    flow = _clean(_value(query, "flow"))
    if not flow:
        return True
    if flow != "xtls-rprx-vision":
        return False
    node["flow"] = flow
    return True


def _add_tls(node, query):
    security = (_clean(_value(query, "security")) or "").lower()
    tls_flag = str(_value(query, "tls", "")).lower()

    if security in ("", "none", "false", "0") and tls_flag not in ("1", "true", "yes"):
        return True

    if security not in ("", "tls", "reality") and tls_flag not in ("1", "true", "yes"):
        return False

    tls = {
        "enabled": True,
        "insecure": str(_value(query, "allowInsecure", "0")).lower() in ("1", "true", "yes")
    }

    server_name = _clean(
        _value(
            query,
            "sni",
            _value(query, "serverName", _value(query, "peer", None))
        )
    )
    if server_name:
        tls["server_name"] = server_name

    alpn = _as_list(_value(query, "alpn"))
    if alpn:
        tls["alpn"] = alpn

    fingerprint = _clean(_value(query, "fp"))
    if fingerprint:
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fingerprint
        }

    public_key = _clean(_value(query, "pbk"))
    short_id = _clean(_value(query, "sid", _value(query, "shortId", None)))
    reality_requested = security == "reality" or public_key is not None

    if reality_requested:
        if not public_key:
            return False
        if short_id is not None and not re.fullmatch(r"[0-9a-fA-F]{0,16}", short_id):
            return False
        reality = {
            "enabled": True,
            "public_key": public_key
        }
        if short_id:
            reality["short_id"] = short_id
        tls["reality"] = reality

    node["tls"] = tls
    return True


def _add_ws_transport(node, query):
    path = _value(query, "path", "/") or "/"
    host = _clean(_value(query, "host"))

    matches = re.search(r"\?ed=(\d+)$", path)
    clean_path = path.rsplit("?ed=", 1)[0] if matches else path

    transport = {"type": "ws", "path": clean_path}
    if host:
        transport["headers"] = {"Host": host}
        if node.get("tls") and not node["tls"].get("server_name"):
            node["tls"]["server_name"] = host

    if matches:
        transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        transport["max_early_data"] = int(matches.group(1))

    node["transport"] = transport


def _add_transport(node, query):
    network = (_clean(_value(query, "type")) or "").lower()

    if network in ("xhttp", "splithttp"):
        if ENABLE_XHTTP:
            transport = {"type": "xhttp"}
            path = _clean(_value(query, "path"))
            host = _clean(_value(query, "host"))
            mode = _clean(_value(query, "mode"))
            if path:
                transport["path"] = path
            if host:
                transport["host"] = host
            if mode:
                transport["mode"] = mode
            node["transport"] = transport
            return True
        return False

    if network == "tcp":
        return True

    if network in ("http", "h2"):
        transport = {"type": "http"}
        host = _as_list(_value(query, "host"))
        path = _clean(_value(query, "path"))
        method = _clean(_value(query, "method"))
        if host:
            transport["host"] = host
        if path:
            transport["path"] = path
        if method:
            transport["method"] = method
        node["transport"] = transport
        return True

    if network == "ws":
        _add_ws_transport(node, query)
        return True

    if network == "grpc":
        transport = {"type": "grpc"}
        service_name = _clean(_value(query, "serviceName"))
        if service_name:
            transport["service_name"] = service_name
        node["transport"] = transport
        return True

    if network == "quic":
        quic_security = (_clean(_value(query, "quicSecurity")) or "none").lower()
        if quic_security not in ("", "none"):
            return False
        node["transport"] = {"type": "quic"}
        return True

    if network in ("httpupgrade", "http-upgrade"):
        transport = {"type": "httpupgrade"}
        host = _clean(_value(query, "host"))
        path = _clean(_value(query, "path"))
        if host:
            transport["host"] = host
        if path:
            transport["path"] = path
        node["transport"] = transport
        return True

    return False


def _add_obfs_websocket(node, query):
    path = _value(query, "path", "/") or "/"
    matches = re.search(r"\?ed=(\d+)$", path)
    transport = {
        "type": "ws",
        "path": path.rsplit("?ed=", 1)[0] if matches else path
    }

    host = _clean(
        _value(query, "peer", _value(query, "obfsParam", _value(query, "sni")))
    )
    if host:
        transport["headers"] = {"Host": host}
        if node.get("tls") and not node["tls"].get("server_name"):
            node["tls"]["server_name"] = host

    if matches:
        transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        transport["max_early_data"] = int(matches.group(1))

    node["transport"] = transport


def _add_multiplex(node, query):
    protocol = _clean(_value(query, "protocol"))
    if not protocol:
        return True
    if protocol not in ("smux", "yamux", "h2mux"):
        return False

    max_streams = _clean(_value(query, "max-streams"))
    max_connections = _clean(_value(query, "max-connections"))
    min_streams = _clean(_value(query, "min-streams"))

    if max_streams and (max_connections or min_streams):
        return False

    multiplex = {"enabled": True, "protocol": protocol}

    try:
        if max_streams:
            value = int(max_streams)
            if value < 0:
                return False
            multiplex["max_streams"] = value
        if max_connections:
            value = int(max_connections)
            if value <= 0:
                return False
            multiplex["max_connections"] = value
        if min_streams:
            value = int(min_streams)
            if value < 0:
                return False
            multiplex["min_streams"] = value
    except ValueError:
        return False

    padding = (_clean(_value(query, "padding")) or "").lower()
    if padding in ("true", "1", "yes"):
        multiplex["padding"] = True
    elif padding not in ("", "false", "0", "no"):
        return False

    node["multiplex"] = multiplex
    return True


def _parse_server(netloc):
    if "@" not in netloc:
        return None

    uuid, address = netloc.rsplit("@", 1)
    uuid = unquote(uuid.strip())
    address = address.strip()
    if not uuid or not address:
        return None

    if address.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:(\d+)", address)
    else:
        match = re.fullmatch(r"(.+):(\d+)", address)
    if not match:
        return None

    server = match.group(1).strip()
    try:
        server_port = int(match.group(2))
    except ValueError:
        return None

    if not server or not 1 <= server_port <= 65535:
        return None
    return uuid, server, server_port


def _decode_netloc(netloc):
    parsed = _parse_server(netloc)
    if parsed:
        return parsed
    try:
        decoded = tool.b64Decode(netloc).decode("utf-8").strip()
    except Exception:
        return None
    return _parse_server(decoded)


def parse(data):
    if not isinstance(data, str):
        return None
    info = data.strip()
    if not info.lower().startswith("vless://"):
        return None

    server_info = urlparse(info)
    parsed_server = _decode_netloc(server_info.netloc)
    if not parsed_server:
        return None

    uuid, server, server_port = parsed_server

    netquery = {
        key: value if len(value) > 1 else value[0]
        for key, value in parse_qs(server_info.query, keep_blank_values=True).items()
    }

    remarks_raw = netquery.get("remarks")
    if remarks_raw is not None:
        remarks = _value(netquery, "remarks")
    else:
        remarks = unquote(server_info.fragment)

    node = {
        "tag": remarks or tool.genName() + "_vless",
        "type": "vless",
        "server": server,
        "server_port": server_port,
        "uuid": uuid
    }

    if not _add_packet_encoding(node, netquery):
        return None
    if not _add_flow(node, netquery):
        return None
    if not _add_tls(node, netquery):
        return None

    if _value(netquery, "type"):
        if not _add_transport(node, netquery):
            return None
    elif (_clean(_value(netquery, "obfs")) or "").lower() == "websocket":
        _add_obfs_websocket(node, netquery)

    if not _add_multiplex(node, netquery):
        return None

    return node
