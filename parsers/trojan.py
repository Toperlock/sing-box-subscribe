import re
from urllib.parse import urlparse, parse_qs, unquote

import tool


def parse(data):
    if not isinstance(data, str):
        return None

    info = data.strip()
    if not info.lower().startswith("trojan://"):
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

        # 从最后一个 @ 分割，避免 password 中存在编码后的 %40
        credentials, address = server_info.netloc.rsplit("@", 1)

        if not credentials or not address:
            return None

        password = unquote(credentials)

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
                or tool.genName() + "_trojan"
            ),
            "type": "trojan",
            "server": re.sub(r"\[|\]", "", server),
            "server_port": server_port,
            "password": password,
            "tls": {
                "enabled": True,
                "insecure": False
            }
        }

        if netquery.get("allowInsecure") == "1":
            node["tls"]["insecure"] = True

        if netquery.get("alpn"):
            node["tls"]["alpn"] = (
                netquery["alpn"]
                .strip("{}")
                .split(",")
            )

        if netquery.get("sni"):
            node["tls"]["server_name"] = netquery["sni"]

        if netquery.get("fp"):
            node["tls"]["utls"] = {
                "enabled": True,
                "fingerprint": netquery["fp"]
            }

        if netquery.get("type"):
            if netquery["type"] == "h2":
                node["transport"] = {
                    "type": "http",
                    "path": netquery.get("path", "/")
                }

                host_val = netquery.get(
                    "host",
                    node["server"]
                )

                if host_val:
                    node["transport"]["host"] = (
                        host_val.split(",")
                        if isinstance(host_val, str)
                        else host_val
                    )

            elif netquery["type"] == "ws":
                ws_path = netquery.get("path", "/")

                matches = re.search(
                    r"\?ed=(\d+)$",
                    ws_path
                )

                node["transport"] = {
                    "type": "ws",
                    "path": (
                        ws_path.rsplit("?ed=", 1)[0]
                        if matches
                        else ws_path
                    )
                }

                if netquery.get("host"):
                    node["transport"]["headers"] = {
                        "Host": netquery["host"]
                    }

            elif netquery["type"] == "grpc":
                node["transport"] = {
                    "type": "grpc",
                    "service_name": netquery.get(
                        "serviceName",
                        ""
                    )
                }

        if netquery.get("protocol") in {
            "smux",
            "yamux",
            "h2mux"
        }:
            node["multiplex"] = {
                "enabled": True,
                "protocol": netquery["protocol"]
            }

            if netquery.get("max-streams"):
                try:
                    node["multiplex"]["max_streams"] = int(
                        netquery["max-streams"]
                    )
                except (TypeError, ValueError):
                    return None

            else:
                try:
                    node["multiplex"]["max_connections"] = int(
                        netquery["max-connections"]
                    )
                    node["multiplex"]["min_streams"] = int(
                        netquery["min-streams"]
                    )
                except (TypeError, ValueError):
                    return None

            if netquery.get("padding") == "True":
                node["multiplex"]["padding"] = True

        return node

    except (
        TypeError,
        ValueError,
        UnicodeError
    ):
        return None
