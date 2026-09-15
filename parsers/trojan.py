import re
from urllib.parse import urlparse, parse_qs, unquote

import tool


def parse(data):
    if not isinstance(data, str):
        return None

    info = data.strip()
    if not info.lower().startswith("tuic://"):
        return None

    try:
        server_info = urlparse(info)

        if server_info.path:
            server_info = server_info._replace(
                netloc=server_info.netloc + server_info.path,
                path=""
            )

        if "@" not in server_info.netloc:
            return None

        credentials, address = server_info.netloc.rsplit("@", 1)

        if not credentials or not address:
            return None

        # 必须在 percent-decoding 前分割 :
        # 防止密码中的 %3A 被误认为结构分隔符
        credential_parts = credentials.split(":", 1)

        uuid = unquote(
            credential_parts[0]
        ).strip()

        password = (
            unquote(credential_parts[1])
            if len(credential_parts) > 1
            else ""
        )

        if not uuid:
            return None

        # IPv6
        if address.startswith("["):
            match = re.fullmatch(
                r"\[([^\]]+)\]:(\d+)(?:/.*)?",
                address
            )
        else:
            match = re.fullmatch(
                r"(.+):(\d+)(?:/.*)?",
                address
            )

        if not match:
            return None

        server = match.group(1).strip()

        try:
            server_port = int(match.group(2))
        except (TypeError, ValueError):
            return None

        if not server or not 1 <= server_port <= 65535:
            return None

        netquery = {
            k: v if len(v) > 1 else v[0]
            for k, v in parse_qs(
                server_info.query,
                keep_blank_values=True
            ).items()
        }

        node = {
            "tag": (
                unquote(server_info.fragment)
                or tool.genName() + "_tuic"
            ),
            "type": "tuic",
            "server": re.sub(r"\[|\]", "", server),
            "server_port": server_port,
            "uuid": uuid,
            "password": (
                password
                if password
                else netquery.get("password", "")
            ),
            "congestion_control": netquery.get(
                "congestion_control",
                "bbr"
            ),
            "udp_relay_mode": netquery.get(
                "udp_relay_mode",
                "native"
            ),
            "zero_rtt_handshake": False,
            "heartbeat": "10s",
            "tls": {
                "enabled": True,
                "alpn": (
                    netquery.get("alpn") or "h3"
                ).strip("{}").split(","),
                "insecure": False
            }
        }

        if str(
            netquery.get("allow_insecure")
        ).lower() in {
            "1",
            "true"
        }:
            node["tls"]["insecure"] = True

        if str(
            netquery.get("disable_sni")
        ) != "1":
            sni_val = netquery.get(
                "sni",
                netquery.get("peer", "")
            )
            if sni_val:
                node["tls"]["server_name"] = sni_val

        if netquery.get("mport"):
            node["server_ports"] = [
                str(netquery["mport"]).replace(
                    "-",
                    ":"
                )
            ]
            node.pop("server_port", None)

        return node

    except (
        TypeError,
        ValueError,
        UnicodeError
    ):
        return None
