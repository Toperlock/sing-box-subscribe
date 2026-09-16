import base64
import json
import re
from urllib.parse import quote, unquote, urlencode


def _is_true(value):
    """
    严格解析 Clash boolean。

    避免：
        bool("false") == True
    """
    if value is True:
        return True

    if value is False or value is None:
        return False

    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _quote_uri(value):
    """
    对 URI 动态字段进行规范化的 percent-encoding。

    规则：
    1. 先解码已有 percent-encoding，避免二次编码；
       例如 %40 -> @ -> %40，而不是 %2540。
    2. 再重新编码为标准 URI value。
    3. 不用于 scheme / host / port 等结构字段。
    """
    if value is None:
        return ""

    text = str(value)

    try:
        text = unquote(text)
    except Exception:
        pass

    return quote(
        text,
        safe="",
    )

def _format_server(server):
    """
    将服务器地址转换成 URI authority 中的正确形式。

    IPv4 / domain:
        example.com
        1.2.3.4

    IPv6:
        2001:db8::1
            ->
        [2001:db8::1]
    """
    if server is None:
        return ""

    server = str(server).strip()

    if not server:
        return ""

    # 已经带 []
    if server.startswith("[") and server.endswith("]"):
        return server

    # URI authority 中 IPv6 必须使用 []
    if ":" in server:
        return f"[{server}]"

    return server


def _parse_port(value, default=None):
    """
    安全解析端口。

    非法端口返回 None，而不是让整个程序因 ValueError 崩溃。
    """
    if value in (None, ""):
        return default

    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None

    if not 1 <= port <= 65535:
        return None

    return port


def _first_port_from_spec(value):
    """
    从 Clash ports 规范中取得第一个有效端口。

    支持例如：
        443
        443-445
        443,8443
    """
    text = str(value or "").strip()

    if not text:
        return None

    first = re.split(
        r"[,-]",
        text,
        maxsplit=1,
    )[0].strip()

    if not first.isdigit():
        return None

    try:
        port = int(first)
    except ValueError:
        return None

    if 1 <= port <= 65535:
        return port

    return None


def _format_alpn(value):
    """
    统一处理 ALPN 的 list / tuple / string 表示。
    """
    if value is None:
        return ""

    if isinstance(value, (list, tuple)):
        values = [
            str(x).strip()
            for x in value
            if str(x).strip()
        ]
    else:
        values = [
            x.strip()
            for x in str(value).split(",")
            if x.strip()
        ]

    # 保序去重
    return ",".join(dict.fromkeys(values))


def _format_port_list(value):
    """
    将 ports 统一转成字符串，但不改变端口范围语义。
    """
    if value is None:
        return ""

    if isinstance(value, (list, tuple)):
        return ",".join(
            str(x).strip()
            for x in value
            if str(x).strip()
        )

    return str(value).strip()


def _format_bandwidth(value):
    """
    将常见 Clash 带宽表示转换成整数 Mbps。

    例如：
        100
        100mbps
        1gbps
        500k
    """
    if value is None:
        return ""

    if isinstance(value, bool):
        return ""

    text = str(value).strip().lower()

    if not text:
        return ""

    match = re.fullmatch(
        r"(\d+(?:\.\d+)?)\s*"
        r"(gbps|gbit|g|mbps|mbit|m|kbps|k)?",
        text,
    )

    if not match:
        return ""

    number = float(match.group(1))
    unit = match.group(2) or "mbps"

    factor = {
        "gbps": 1000,
        "gbit": 1000,
        "g": 1000,
        "mbps": 1,
        "mbit": 1,
        "m": 1,
        "kbps": 0.001,
        "k": 0.001,
    }[unit]

    mbps = number * factor

    if mbps < 0:
        return ""

    return str(
        max(
            0,
            int(round(mbps)),
        )
    )

def _format_hop_interval(value):
    """
    将 Mihomo Hysteria2 的 hop-interval 统一转换成
    sing-box 可使用的 duration。

    支持：

        30
            -> ("30s", None)

        "30"
            -> ("30s", None)

        "15-30"
            -> ("15s", "30s")

        "30s"
            -> ("30s", None)

        "1m"
            -> ("1m", None)

    返回：

        (hop_interval, hop_interval_max)

    非法值：
        (None, None)
    """
    if value in (None, ""):
        return None, None

    if isinstance(value, bool):
        return None, None

    text = str(value).strip().lower()

    if not text:
        return None, None

    # ------------------------------------------------------------
    # 单个数字：
    #
    # Mihomo:
    #   hop-interval: 30
    #
    # sing-box:
    #   hop_interval: 30s
    # ------------------------------------------------------------
    if re.fullmatch(r"\d+", text):
        seconds = int(text)

        if seconds <= 0:
            return None, None

        return f"{seconds}s", None

    # ------------------------------------------------------------
    # 范围：
    #
    # Mihomo:
    #   hop-interval: 15-30
    #
    # sing-box 1.14:
    #   hop_interval: 15s
    #   hop_interval_max: 30s
    # ------------------------------------------------------------
    match = re.fullmatch(
        r"(\d+)\s*-\s*(\d+)",
        text,
    )

    if match:
        minimum = int(match.group(1))
        maximum = int(match.group(2))

        if minimum <= 0:
            return None, None

        if maximum < minimum:
            return None, None

        return (
            f"{minimum}s",
            f"{maximum}s",
        )

    # ------------------------------------------------------------
    # 已经是 duration：
    #
    # 例如：
    #   30s
    #   1m
    #   500ms
    # ------------------------------------------------------------
    if re.fullmatch(
        r"(?:0|[1-9]\d*)(?:ns|us|µs|ms|s|m|h)",
        text,
    ):
        return text, None

    return None, None

def _get_header_value(headers, target):
    """
    大小写不敏感地读取 HTTP header。
    """
    if not isinstance(headers, dict):
        return ""

    target = str(target).lower()

    for key, value in headers.items():
        if str(key).lower() == target:
            return str(value)

    return ""


def _safe_name(value, default=""):
    """
    安全处理节点名称。
    """
    if value is None:
        return default

    try:
        return str(value)
    except Exception:
        return default


def clash2v2ray(original_share_link):
    """
    将 Clash/Mihomo 节点转换成 v2ray-style share link。

    注意：
    这里的输出并不是直接的 sing-box JSON，而是后续 parser
    使用的 URI 中间格式。
    """
    if not isinstance(original_share_link, dict):
        return None

    share_link = original_share_link.copy()
    link = ""

    node_type = share_link.get("type")

    if not node_type:
        return None

    # ------------------------------------------------------------
    # port fallback
    # ------------------------------------------------------------
    #
    # 只在没有 port 时从 ports 取得第一个端口。
    # Hysteria2 专用分支仍会保留完整 ports -> mport。
    #
    if (
        "port" not in share_link
        or share_link.get("port") in (None, "")
    ):
        if "ports" in share_link:
            first_port = _first_port_from_spec(
                share_link.get("ports")
            )

            if first_port is not None:
                share_link["port"] = first_port

    # ============================================================
    # VMess
    # ============================================================
    if node_type == "vmess":
        try:
            name = _safe_name(
                share_link.get("name")
            )

            server = str(
                share_link.get("server", "")
            ).strip()

            uuid = str(
                share_link.get("uuid", "")
            ).strip()

            port = _parse_port(
                share_link.get("port")
            )

            if not server or not uuid or port is None:
                return None

            vmess_info = {
                "v": "2",
                "ps": name,
                "add": server,
                "port": port,
                "id": uuid,
                "aid": share_link.get(
                    "alterId",
                    0,
                ),
                "net": share_link.get(
                    "network",
                    "tcp",
                ),
                "scy": share_link.get(
                    "cipher",
                    "auto",
                ),
                "type": "none",
                "host": _get_header_value(
                    (
                        share_link.get(
                            "ws-opts",
                            {},
                        ) or {}
                    ).get(
                        "headers",
                        {},
                    ),
                    "Host",
                ) or _get_header_value(
                    share_link.get(
                        "ws-headers",
                        {},
                    ) or {},
                    "Host",
                ),
                "path": (
                    share_link.get(
                        "ws-path",
                        "",
                    )
                    or (
                        share_link.get(
                            "ws-opts",
                            {},
                        ) or {}
                    ).get(
                        "path",
                        "",
                    )
                ),
                "tls": "",
            }

            if share_link.get(
                "skip-cert-verify"
            ) is False:
                vmess_info["verify_cert"] = False

            if (
                share_link.get("tls")
                and share_link.get("tls") is not False
            ):
                vmess_info["tls"] = "tls"
                vmess_info["sni"] = str(
                    share_link.get(
                        "servername",
                        "",
                    )
                    or ""
                )

            network = str(
                vmess_info["net"]
                or "tcp"
            ).lower()

            if network == "grpc":
                grpc_opts = (
                    share_link.get(
                        "grpc-opts",
                        {},
                    )
                    or {}
                )

                vmess_info["type"] = (
                    grpc_opts.get(
                        "grpc-mode"
                    )
                )

                service_name = grpc_opts.get(
                    "grpc-service-name"
                )

                if service_name != "/":
                    vmess_info["path"] = (
                        service_name
                    )
                else:
                    vmess_info["path"] = ""

            elif network == "h2":
                h2_opts = (
                    share_link.get(
                        "h2-opts",
                        {},
                    )
                    or {}
                )

                vmess_info["host"] = (
                    h2_opts.get(
                        "host",
                        [],
                    )
                )

                vmess_info["path"] = (
                    h2_opts.get(
                        "path",
                        "",
                    )
                )

            elif network == "http":
                http_opts = (
                    share_link.get(
                        "http-opts",
                        {},
                    )
                    or {}
                )

                headers = (
                    http_opts.get(
                        "headers",
                        {},
                    )
                    or {}
                )

                vmess_info["headers"] = headers

                vmess_info["host"] = (
                    _get_header_value(
                        headers,
                        "Host",
                    )
                    or []
                )

                vmess_info["path"] = (
                    http_opts.get(
                        "path",
                        [],
                    )
                )

            smux = (
                share_link.get(
                    "smux",
                    {},
                )
                or {}
            )

            if smux.get("enabled") is True:
                vmess_info["protocol"] = smux.get(
                    "protocol",
                    "",
                )
                vmess_info["max_connections"] = (
                    smux.get(
                        "max-connections",
                        "",
                    )
                )
                vmess_info["min_streams"] = (
                    smux.get(
                        "min-streams",
                        "",
                    )
                )
                vmess_info["max_streams"] = (
                    smux.get(
                        "max-streams",
                        "",
                    )
                )
                vmess_info["padding"] = (
                    smux.get(
                        "padding",
                        "",
                    )
                )

            vmess_json = json.dumps(
                vmess_info,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")

            vmess_base64 = (
                base64.b64encode(
                    vmess_json
                ).decode("utf-8")
            )

            return (
                f"vmess://"
                f"{vmess_base64}"
            )

        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeError,
        ):
            return None

    # ============================================================
    # Shadowsocks
    # ============================================================
    elif node_type == "ss":
        cipher = str(
            share_link.get(
                "cipher",
                "",
            )
            or ""
        )

        password = str(
            share_link.get(
                "password",
                "",
            )
            or ""
        )

        server = _format_server(
            share_link.get("server")
        )

        port = _parse_port(
            share_link.get("port")
        )

        name = _safe_name(
            share_link.get("name")
        )

        if (
            not cipher
            or not server
            or port is None
        ):
            return None

        user_info = (
            f"{cipher}:{password}"
        )

        base_link = (
            base64.b64encode(
                user_info.encode("utf-8")
            ).decode("utf-8")
        )

        plugin = share_link.get(
            "plugin"
        )

        url_link = ""

        if plugin:
            plugin_opts = (
                share_link.get(
                    "plugin-opts",
                    {},
                )
                or {}
            )

            if plugin in {
                "obfs",
                "obfs-local",
            }:
                mode = plugin_opts.get(
                    "mode",
                    "",
                )

                host = plugin_opts.get(
                    "host",
                    "",
                )

                plugin_value = (
                    f"obfs-local;"
                    f"obfs={mode};"
                    f"obfs-host={host}"
                )

                url_link = (
                    "?plugin="
                    + _quote_uri(
                        plugin_value
                    )
                )

            elif plugin == "v2ray-plugin":
                v2ray_plugin = {
                    "mode": plugin_opts.get(
                        "mode",
                        "",
                    ),
                    "host": plugin_opts.get(
                        "host",
                        "",
                    ),
                    "path": plugin_opts.get(
                        "path",
                        "",
                    ),
                    "headers": plugin_opts.get(
                        "headers",
                        "",
                    ),
                    "fingerprint": plugin_opts.get(
                        "fingerprint",
                        "",
                    ),
                    "mux": (
                        plugin_opts.get(
                            "mux"
                        )
                        is True
                    ),
                    "skip-cert-verify": (
                        plugin_opts.get(
                            "skip-cert-verify"
                        )
                        is True
                    ),
                    "tls": (
                        plugin_opts.get(
                            "tls"
                        )
                        is True
                    ),
                }

                encoded_plugin = (
                    base64.b64encode(
                        json.dumps(
                            v2ray_plugin,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).decode("ascii")
                )

                url_link = (
                    f"?v2ray-plugin="
                    f"{encoded_plugin}"
                )

            elif plugin == "shadow-tls":
                shadowtls = {
                    "version": plugin_opts.get(
                        "version",
                        "",
                    ),
                    "host": plugin_opts.get(
                        "host",
                        "",
                    ),
                    "password": plugin_opts.get(
                        "password",
                        "",
                    ),
                    "fp": share_link.get(
                        "client-fingerprint",
                        "",
                    ),
                }

                encoded_shadowtls = (
                    base64.b64encode(
                        json.dumps(
                            shadowtls,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).decode("ascii")
                )

                url_link = (
                    f"?shadow-tls="
                    f"{encoded_shadowtls}"
                )

        link = (
            f"ss://"
            f"{base_link}@"
            f"{server}:{port}"
            f"{url_link}"
        )

        smux = (
            share_link.get(
                "smux",
                {},
            )
            or {}
        )

        if smux.get("enabled") is True:
            smux_params = {
                "protocol": smux.get(
                    "protocol",
                    "",
                ),
                "max-connections": smux.get(
                    "max-connections",
                    "",
                ),
                "min-streams": smux.get(
                    "min-streams",
                    "",
                ),
                "max-streams": smux.get(
                    "max-streams",
                    "",
                ),
                "padding": smux.get(
                    "padding",
                    "",
                ),
            }

            smux_params = {
                key: str(value)
                for key, value in smux_params.items()
                if value not in ("", None)
            }

            if smux_params:
                separator = "?" if "?" not in link else "&"

                link += (
                    separator
                    + urlencode(
                        smux_params
                    )
                )

        elif share_link.get(
            "udp-over-tcp"
        ) is True:
            separator = "?" if "?" not in link else "&"

            link += (
                f"{separator}uot=1"
            )

        link += (
            "#"
            + _quote_uri(name)
        )

        return link

    # ============================================================
    # ShadowsocksR
    # ============================================================
    elif node_type == "ssr":
        server = str(
            share_link.get(
                "server",
                "",
            )
            or ""
        )

        port = _parse_port(
            share_link.get("port")
        )

        if not server or port is None:
            return None

        password = base64.b64encode(
            str(
                share_link.get(
                    "password",
                    "",
                )
                or ""
            ).encode("utf-8")
        ).decode("ascii")

        obfs_param = share_link.get(
            "obfs-param"
        )

        if obfs_param is None:
            obfs_param = ""

        obfs_param = base64.b64encode(
            str(
                obfs_param
            ).encode("utf-8")
        ).decode("ascii")

        protocol_param = base64.b64encode(
            str(
                share_link.get(
                    "protocol-param",
                    "",
                )
                or ""
            ).encode("utf-8")
        ).decode("ascii")

        remarks = base64.b64encode(
            _safe_name(
                share_link.get(
                    "name",
                    "",
                )
            ).encode("utf-8")
        ).decode("ascii")

        group = base64.b64encode(
            str(
                share_link.get(
                    "group",
                    "",
                )
                or ""
            ).encode("utf-8")
        ).decode("ascii")

        ssr_info = {
            "server": server,
            "port": port,
            "protocol": str(
                share_link.get(
                    "protocol",
                    "",
                )
                or ""
            ),
            "cipher": str(
                share_link.get(
                    "cipher",
                    "",
                )
                or ""
            ),
            "obfs": str(
                share_link.get(
                    "obfs",
                    "",
                )
                or ""
            ),
            "password": password,
            "obfsparam": obfs_param,
            "protoparam": protocol_param,
            "remarks": remarks,
            "group": group,
        }

        raw = (
            "{server}:{port}:"
            "{protocol}:{cipher}:{obfs}:"
            "{password}/?"
            "obfsparam={obfsparam}&"
            "protoparam={protoparam}&"
            "remarks={remarks}&"
            "group={group}"
        ).format(
            **ssr_info
        )

        base_link = base64.b64encode(
            raw.encode("utf-8")
        ).decode("ascii")

        return f"ssr://{base_link}"

    # ============================================================
    # Trojan
    # ============================================================
    elif node_type == "trojan":
        server = _format_server(
            share_link.get("server")
        )

        port = _parse_port(
            share_link.get("port")
        )

        password = str(
            share_link.get(
                "password",
                "",
            )
            or ""
        )

        if (
            not server
            or port is None
            or not password
        ):
            return None

        network = str(
            share_link.get(
                "network",
                "tcp",
            )
            or "tcp"
        ).lower()

        sni = str(
            share_link.get(
                "sni",
                "",
            )
            or ""
        )

        params = {
            "sni": sni,
            "allowInsecure": (
                "1"
                if _is_true(
                    share_link.get(
                        "skip-cert-verify"
                    )
                )
                else "0"
            ),
            "type": network,
            "fp": str(
                share_link.get(
                    "client-fingerprint",
                    "",
                )
                or ""
            ),
        }

        alpn = _format_alpn(
            share_link.get("alpn")
        )

        if alpn:
            params["alpn"] = alpn

        if network == "grpc":
            grpc_opts = (
                share_link.get(
                    "grpc-opts",
                    {},
                )
                or {}
            )

            service_name = str(
                grpc_opts.get(
                    "grpc-service-name",
                    "",
                )
                or ""
            )

            if service_name not in {
                "",
                "/",
                "none",
            }:
                params["serviceName"] = service_name
            else:
                server_plain = str(
                    share_link.get(
                        "server",
                        "",
                    )
                    or ""
                )

                server_parts = (
                    server_plain.split(".")
                )

                if (
                    len(server_parts) >= 2
                    and not server_parts[-2].isdigit()
                ):
                    params["serviceName"] = (
                        server_parts[-2]
                    )

        elif network == "ws":
            ws_opts = (
                share_link.get(
                    "ws-opts",
                    {},
                )
                or {}
            )

            path = (
                ws_opts.get(
                    "path",
                    "",
                )
                or ""
            )

            headers = (
                ws_opts.get(
                    "headers",
                    {},
                )
                or {}
            )

            host = _get_header_value(
                headers,
                "Host",
            )

            if not host:
                host = sni

            params["host"] = host
            params["path"] = path

        elif network != "tcp":
            return None

        query = urlencode(
            {
                key: value
                for key, value in params.items()
                if value not in (None, "")
            },
            doseq=True,
        )

        link = (
            f"trojan://"
            f"{_quote_uri(password)}@"
            f"{server}:{port}"
        )

        if query:
            link += f"?{query}"

        # SMUX
        smux = (
            share_link.get(
                "smux",
                {},
            )
            or {}
        )

        if smux.get("enabled") is True:
            smux_params = {
                "protocol": smux.get(
                    "protocol",
                    "",
                ),
                "max-connections": smux.get(
                    "max-connections",
                    "",
                ),
                "min-streams": smux.get(
                    "min-streams",
                    "",
                ),
                "max-streams": smux.get(
                    "max-streams",
                    "",
                ),
                "padding": smux.get(
                    "padding",
                    "",
                ),
            }

            smux_params = {
                key: str(value)
                for key, value in smux_params.items()
                if value not in ("", None)
            }

            if smux_params:
                link += (
                    "&"
                    + urlencode(
                        smux_params
                    )
                )

        link += (
            "#"
            + _quote_uri(
                share_link.get(
                    "name",
                    "",
                )
            )
        )

        return link

    # ============================================================
    # VLESS
    # ============================================================
    elif node_type == "vless":
        """
        Clash/Mihomo VLESS -> VLESS share link.

        设计目标：

        1. 不把 XHTTP / SplitHTTP 伪装成 HTTP/WS
        2. 保留 TLS / Reality / uTLS / ALPN / flow
        3. 保留 packet-encoding
        4. Query 参数统一 percent-encoding
        5. IPv6 正确使用 []
        """

        network = str(
            share_link.get(
                "network",
                "tcp",
            )
            or "tcp"
        ).strip().lower()

        # 不能将 XHTTP 错误降级为 WS / HTTP。
        if network in {
            "xhttp",
            "splithttp",
        }:
            return None

        if network not in {
            "tcp",
            "ws",
            "grpc",
        }:
            return None

        server = str(
            share_link.get(
                "server",
                "",
            )
            or ""
        ).strip()

        if not server:
            return None

        uri_server = _format_server(
            server
        )

        uuid = str(
            share_link.get(
                "uuid",
                "",
            )
            or ""
        ).strip()

        if not uuid:
            return None

        port = _parse_port(
            share_link.get("port")
        )

        if port is None:
            return None

        # --------------------------------------------------------
        # TLS / Reality
        # --------------------------------------------------------

        tls_enabled = _is_true(
            share_link.get("tls")
        )

        security = (
            "tls"
            if tls_enabled
            else "none"
        )

        reality_opts = (
            share_link.get(
                "reality-opts"
            )
            or {}
        )

        if not isinstance(
            reality_opts,
            dict,
        ):
            return None

        public_key = ""
        short_id = ""

        if reality_opts:
            public_key = str(
                reality_opts.get(
                    "public-key",
                    "",
                )
                or ""
            ).strip()

            short_id = str(
                reality_opts.get(
                    "short-id",
                    "",
                )
                or ""
            ).strip()

            if not public_key:
                return None

            # Reality shortId 为十六进制，最大 8 字节。
            if short_id:
                if not re.fullmatch(r"[0-9a-fA-F]{0,16}", short_id):
                    return False
                if len(short_id) % 2 != 0:
                    return False

            security = "reality"

        sni = (
            share_link.get(
                "servername"
            )
            or share_link.get(
                "sni"
            )
            or ""
        )

        fp = (
            share_link.get(
                "client-fingerprint"
            )
            or ""
        )

        flow = (
            share_link.get(
                "flow"
            )
            or ""
        )

        skip_cert_verify = _is_true(
            share_link.get(
                "skip-cert-verify"
            )
        )

        params = {
            "encryption": "none",
            "security": security,
            "sni": str(sni),
            "fp": str(fp),
            "type": network,
            "flow": str(flow),
            "allowInsecure": (
                "1"
                if skip_cert_verify
                else "0"
            ),
        }

        # --------------------------------------------------------
        # packet-encoding
        # --------------------------------------------------------

        packet_encoding = (
            share_link.get(
                "packet-encoding"
            )
            or share_link.get(
                "packetEncoding"
            )
            or ""
        )

        if packet_encoding:
            params[
                "packetEncoding"
            ] = str(packet_encoding)

        # --------------------------------------------------------
        # ALPN
        # --------------------------------------------------------

        alpn = _format_alpn(
            share_link.get("alpn")
        )

        if alpn:
            params["alpn"] = alpn

        # --------------------------------------------------------
        # Reality
        # --------------------------------------------------------

        if reality_opts:
            params["pbk"] = public_key

            if short_id:
                params["sid"] = short_id

        # --------------------------------------------------------
        # WebSocket
        # --------------------------------------------------------

        if network == "ws":
            ws_opts = (
                share_link.get(
                    "ws-opts",
                    {},
                )
                or {}
            )

            if not isinstance(
                ws_opts,
                dict,
            ):
                return None

            path = (
                ws_opts.get(
                    "path"
                )
                or share_link.get(
                    "ws-path"
                )
                or "/"
            )

            headers = (
                ws_opts.get(
                    "headers",
                    {},
                )
                or {}
            )

            if not isinstance(
                headers,
                dict,
            ):
                return None

            host = _get_header_value(
                headers,
                "Host",
            )

            params["path"] = str(
                path
            )

            if host:
                params["host"] = host

        # --------------------------------------------------------
        # gRPC
        # --------------------------------------------------------

        elif network == "grpc":
            grpc_opts = (
                share_link.get(
                    "grpc-opts",
                    {},
                )
                or {}
            )

            if not isinstance(
                grpc_opts,
                dict,
            ):
                return None

            service_name = str(
                grpc_opts.get(
                    "grpc-service-name",
                    "",
                )
                or ""
            )

            if service_name in {
                "",
                "/",
            }:
                service_name = ""

            if service_name:
                params[
                    "serviceName"
                ] = service_name

        query = urlencode(
            params,
            doseq=True,
        )

        link = (
            f"vless://"
            f"{_quote_uri(uuid)}@"
            f"{uri_server}:{port}"
        )

        if query:
            link += f"?{query}"

        # --------------------------------------------------------
        # SMUX
        # --------------------------------------------------------

        smux = (
            share_link.get(
                "smux",
                {},
            )
            or {}
        )

        if not isinstance(
            smux,
            dict,
        ):
            return None

        if smux.get(
            "enabled"
        ) is True:
            smux_params = {
                "protocol": smux.get(
                    "protocol",
                    "",
                ),
                "max-connections": smux.get(
                    "max-connections",
                    "",
                ),
                "min-streams": smux.get(
                    "min-streams",
                    "",
                ),
                "max-streams": smux.get(
                    "max-streams",
                    "",
                ),
                "padding": smux.get(
                    "padding",
                    "",
                ),
            }

            smux_params = {
                key: str(value)
                for key, value in smux_params.items()
                if value not in ("", None)
            }

            if smux_params:
                link += (
                    "&"
                    + urlencode(
                        smux_params
                    )
                )

        link += (
            "#"
            + _quote_uri(
                share_link.get(
                    "name",
                    "",
                )
            )
        )

        return link

    # ============================================================
    # TUIC
    # ============================================================
    elif node_type == "tuic":
        server = _format_server(
            share_link.get("server")
        )

        if not server:
            return None

        port = _parse_port(
            share_link.get(
                "port",
                443,
            ),
            default=443,
        )

        if port is None:
            return None

        uuid = str(
            share_link.get(
                "uuid",
                "",
            )
            or ""
        )

        password = str(
            share_link.get(
                "password",
                "",
            )
            or ""
        )

        if not uuid or not password:
            return None

        params = {
            "sni": share_link.get(
                "sni",
                "",
            ),
            "alpn": _format_alpn(
                share_link.get("alpn")
            ),
            "allow_insecure": (
                "1"
                if _is_true(
                    share_link.get(
                        "skip-cert-verify"
                    )
                )
                else "0"
            ),
            "congestion_control": share_link.get(
                "congestion-controller",
                "bbr",
            ),
            "udp_relay_mode": share_link.get(
                "udp-relay-mode",
                "native",
            ),
        }

        mport = _format_port_list(
            share_link.get("ports")
        )

        if mport:
            params["mport"] = mport

        query_string = urlencode(
            {
                key: value
                for key, value in params.items()
                if value not in (None, "")
            },
            doseq=True,
        )

        link = (
            f"tuic://"
            f"{_quote_uri(uuid)}:"
            f"{_quote_uri(password)}@"
            f"{server}:{port}"
        )

        if query_string:
            link += f"?{query_string}"

        link += (
            "#"
            + _quote_uri(
                share_link.get(
                    "name",
                    "",
                )
            )
        )

        return link

    # ============================================================
    # Hysteria
    # ============================================================
    elif node_type == "hysteria":
        server = _format_server(
            share_link.get("server")
        )

        if not server:
            return None

        port = _parse_port(
            share_link.get("port")
        )

        if port is None:
            return None

        auth = share_link.get(
            "auth_str",
            share_link.get(
                "auth-str",
                "",
            ),
        )

        params = {
            "protocol": share_link.get(
                "protocol",
                "udp",
            ),
            "insecure": (
                "1"
                if _is_true(
                    share_link.get(
                        "skip-cert-verify"
                    )
                )
                else "0"
            ),
            "peer": share_link.get(
                "sni",
                "",
            ),
            "obfs": share_link.get(
                "obfs",
                "",
            ),
        }

        alpn = _format_alpn(
            share_link.get("alpn")
        )

        if alpn:
            params["alpn"] = alpn

        # --------------------------------------------------------
        # bandwidth
        #
        # Mihomo:
        #   up: "30 Mbps"
        #   down: "200 Mbps"
        #
        # 中间 URI:
        #   upmbps=30
        #   downmbps=200
        # --------------------------------------------------------
        up_mbps = _format_bandwidth(
            share_link.get(
                "upmbps",
                share_link.get(
                    "up"
                ),
            )
        )

        down_mbps = _format_bandwidth(
            share_link.get(
                "downmbps",
                share_link.get(
                    "down"
                ),
            )
        )

        if up_mbps:
            query_params.append(
                (
                    "upmbps",
                    up_mbps,
                )
            )

        if down_mbps:
            query_params.append(
                (
                    "downmbps",
                    down_mbps,
                )
            )

        # --------------------------------------------------------
        # hop_interval
        #
        # Mihomo:
        #   hop-interval: 30
        #   hop-interval: "15-30"
        #
        # 中间 URI:
        #   hop_interval=30s
        #
        # 或：
        #   hop_interval=15s
        #   hop_interval_max=30s
        # --------------------------------------------------------
        hop_interval_value = None

        for key in (
            "hop_interval",
            "hopInterval",
        ):
            value = share_link.get(key)

            if value not in (
                None,
                "",
            ):
                hop_interval_value = value
                break

        if hop_interval_value is not None:
            hop_interval, hop_interval_max = (
                _format_hop_interval(
                    hop_interval_value
                )
            )

            if hop_interval is None:
                return None

            query_params.append(
                (
                    "hop_interval",
                    hop_interval,
                )
            )

            if hop_interval_max is not None:
                query_params.append(
                    (
                        "hop_interval_max",
                        hop_interval_max,
                    )
                )

        # --------------------------------------------------------
        # 显式 hop_interval_max
        #
        # 只有 hop-interval 本身没有使用：
        #
        #   15-30
        #
        # 才读取单独的 hop_interval_max。
        # --------------------------------------------------------
        else:
            explicit_hop_max = None

            for key in (
                "hop_interval_max",
                "hopIntervalMax",
            ):
                value = share_link.get(key)

                if value not in (
                    None,
                    "",
                ):
                    explicit_hop_max = value
                    break

            if explicit_hop_max is not None:
                hop_interval_max, _ = (
                    _format_hop_interval(
                        explicit_hop_max
                    )
                )

                if hop_interval_max is None:
                    return None

                query_params.append(
                    (
                        "hop_interval_max",
                        hop_interval_max,
                    )
                )

        # --------------------------------------------------------
        # Compatibility extensions
        # --------------------------------------------------------
        extra_keys = (
            (
                "bbr_profile",
                (
                    "bbr_profile",
                    "bbrProfile",
                ),
            ),
            (
                "brutal_debug",
                (
                    "brutal_debug",
                    "brutalDebug",
                ),
            ),
            (
                "disable_chrome_parrot",
                (
                    "disable_chrome_parrot",
                    "disableChromeParrot",
                ),
            ),
            (
                "network",
                (
                    "network",
                ),
            ),
            (
                "obfs-min-packet-size",
                (
                    "obfs-min-packet-size",
                    "obfs_min_packet_size",
                ),
            ),
            (
                "obfs-max-packet-size",
                (
                    "obfs-max-packet-size",
                    "obfs_max_packet_size",
                ),
            ),
        )

        for query_name, keys in extra_keys:
            value = None

            for key in keys:
                if share_link.get(
                    key
                ) not in (
                    None,
                    "",
                ):
                    value = share_link.get(
                        key
                    )
                    break

            if value not in (
                None,
                "",
            ):
                if query_name in {
                    "brutal_debug",
                    "disable_chrome_parrot",
                }:
                    value = (
                        "1"
                        if _is_true(value)
                        else "0"
                    )

                query_params.append(
                    (
                        query_name,
                        value,
                    )
                )

        query_string = urlencode(
            query_params,
            doseq=True,
        )

        link = (
            f"hysteria://"
            f"{server}:{port}"
        )

        if query_string:
            link += f"?{query_string}"

        link += (
            "#"
            + _quote_uri(
                share_link.get(
                    "name",
                    "",
                )
            )
        )

        return link

    # ============================================================
    # Hysteria2
    # ============================================================
    elif node_type == "hysteria2":
        # ========================================================
        # Clash Hysteria2 -> Hysteria2 URI
        #
        # 设计目标：
        # 1. 保留完整 ports/mport
        # 2. 正确处理 IPv6
        # 3. password / query / name 全部编码
        # 4. "false" 不被当成 True
        # 5. ALPN 支持 list / string
        # ========================================================

        server = _format_server(
            share_link.get("server")
        )

        if not server:
            return None

        # Clash 中可能只有 ports，没有 port。
        base_port = share_link.get(
            "port"
        )

        if base_port in (None, ""):
            base_port = _first_port_from_spec(
                share_link.get("ports")
            )

        if base_port in (None, ""):
            base_port = 443

        base_port = _parse_port(
            base_port
        )

        if base_port is None:
            return None

        ports = _format_port_list(
            share_link.get("ports")
        )

        query_params = []

        if _is_true(
            share_link.get(
                "skip-cert-verify"
            )
        ):
            query_params.append(
                (
                    "insecure",
                    "1",
                )
            )

        obfs = str(
            share_link.get(
                "obfs"
            )
            or ""
        ).strip()

        if (
            obfs
            and obfs.lower() != "none"
        ):
            query_params.append(
                (
                    "obfs",
                    obfs,
                )
            )

            obfs_password = share_link.get(
                "obfs-password",
                share_link.get(
                    "obfs_password",
                    "",
                ),
            )

            if obfs_password not in (
                None,
                "",
            ):
                query_params.append(
                    (
                        "obfs-password",
                        obfs_password,
                    )
                )

        # Hysteria2 fingerprint -> pinSHA256
        pin_sha256 = share_link.get(
            "pinSHA256",
            share_link.get(
                "pin-sha256",
                share_link.get(
                    "fingerprint",
                    "",
                ),
            ),
        )

        if pin_sha256 not in (
            None,
            "",
        ):
            query_params.append(
                (
                    "pinSHA256",
                    pin_sha256,
                )
            )

        sni = share_link.get(
            "sni",
            share_link.get(
                "servername",
                share_link.get(
                    "server-name",
                    "",
                ),
            ),
        )

        if sni not in (
            None,
            "",
        ):
            query_params.append(
                (
                    "sni",
                    sni,
                )
            )

        alpn = _format_alpn(
            share_link.get("alpn")
        )

        if alpn:
            query_params.append(
                (
                    "alpn",
                    alpn,
                )
            )

        if ports:
            query_params.append(
                (
                    "mport",
                    ports,
                )
            )
        # --------------------------------------------------------
        # Compatibility extensions
        # --------------------------------------------------------

        extra_keys = (
            (
                "hop_interval",
                (
                    "hop_interval",
                    "hopInterval",
                ),
            ),
            (
                "hop_interval_max",
                (
                    "hop_interval_max",
                    "hopIntervalMax",
                ),
            ),
            (
                "bbr_profile",
                (
                    "bbr_profile",
                    "bbrProfile",
                ),
            ),
            (
                "brutal_debug",
                (
                    "brutal_debug",
                    "brutalDebug",
                ),
            ),
            (
                "disable_chrome_parrot",
                (
                    "disable_chrome_parrot",
                    "disableChromeParrot",
                ),
            ),
            (
                "network",
                (
                    "network",
                ),
            ),
            (
                "obfs-min-packet-size",
                (
                    "obfs-min-packet-size",
                    "obfs_min_packet_size",
                ),
            ),
            (
                "obfs-max-packet-size",
                (
                    "obfs-max-packet-size",
                    "obfs_max_packet_size",
                ),
            ),
        )

        for query_name, keys in extra_keys:
            value = None

            for key in keys:
                if share_link.get(
                    key
                ) not in (
                    None,
                    "",
                ):
                    value = share_link.get(
                        key
                    )
                    break

            if value not in (
                None,
                "",
            ):
                if query_name in {
                    "brutal_debug",
                    "disable_chrome_parrot",
                }:
                    value = (
                        "1"
                        if _is_true(value)
                        else "0"
                    )

                query_params.append(
                    (
                        query_name,
                        value,
                    )
                )

        query_string = urlencode(
            [
                (
                    str(key),
                    str(value),
                )
                for key, value in query_params
                if value not in (
                    None,
                    "",
                )
            ],
            doseq=True,
        )

        auth = share_link.get(
            "password"
        )

        if auth in (
            None,
            "",
        ):
            auth = share_link.get(
                "auth",
                "",
            )

        authority = (
            f"{_quote_uri(auth)}@"
            f"{server}:{base_port}"
            if auth not in (
                None,
                "",
            )
            else
            f"{server}:{base_port}"
        )

        link = (
            f"hysteria2://"
            f"{authority}"
        )

        if query_string:
            link += (
                f"?{query_string}"
            )

        name = share_link.get(
            "name",
            "Hysteria2_Node",
        )

        link += (
            "#"
            + _quote_uri(name)
        )

        return link

    # ============================================================
    # WireGuard
    # ============================================================
    elif node_type == "wireguard":
        server = _format_server(
            share_link.get("server")
        )

        port = _parse_port(
            share_link.get("port")
        )

        public_key = str(
            share_link.get(
                "public-key",
                "",
            )
            or ""
        )

        private_key = str(
            share_link.get(
                "private-key",
                "",
            )
            or ""
        )

        if (
            not server
            or port is None
            or not public_key
            or not private_key
        ):
            return None

        params = {
            "publicKey": public_key,
            "privateKey": private_key,
            "presharedKey": share_link.get(
                "pre-shared-key",
                "",
            ),
            "ip": share_link.get(
                "ip",
                "",
            ),
            "udp": "1",
        }

        ipv6 = share_link.get(
            "ipv6"
        )

        if ipv6:
            ip_value = (
                f"{params['ip']},{ipv6}"
                if params.get("ip")
                else str(ipv6)
            )

            params["ip"] = ip_value

        reserved = share_link.get(
            "reserved"
        )

        if reserved is not None:
            if isinstance(
                reserved,
                str,
            ):
                params["reserved"] = reserved

            elif isinstance(
                reserved,
                (list, tuple),
            ):
                params["reserved"] = ",".join(
                    str(item)
                    for item in reserved
                )

            else:
                return None

        query_string = urlencode(
            {
                key: value
                for key, value in params.items()
                if value not in (
                    None,
                    "",
                )
            },
            doseq=True,
        )

        link = (
            f"wg://"
            f"{server}:{port}"
        )

        if query_string:
            link += (
                f"?{query_string}"
            )

        link += (
            "#"
            + _quote_uri(
                share_link.get(
                    "name",
                    "",
                )
            )
        )

        return link

    # ============================================================
    # HTTP
    # ============================================================
    elif node_type == "http":
        server = _format_server(
            share_link.get("server")
        )

        port = _parse_port(
            share_link.get("port")
        )

        if not server or port is None:
            return None

        username = str(
            share_link.get(
                "username",
                "",
            )
            or ""
        )

        password = str(
            share_link.get(
                "password",
                "",
            )
            or ""
        )

        if username:
            authority = (
                f"{username}:{password}@"
                f"{server}:{port}"
            )
        else:
            authority = (
                f"{server}:{port}"
            )

        base_link = base64.b64encode(
            authority.encode(
                "utf-8"
            )
        ).decode("ascii")

        query_params = {}

        if share_link.get("sni"):
            query_params["sni"] = str(
                share_link.get(
                    "sni"
                )
            )

        query = urlencode(
            query_params,
            doseq=True,
        )

        link = (
            f"http://"
            f"{base_link}"
        )

        if query:
            link += f"?{query}"

        name = share_link.get(
            "name"
        )

        if name:
            link += (
                "#"
                + _quote_uri(name)
            )

        return link

    # ============================================================
    # SOCKS5
    # ============================================================
    elif node_type == "socks5":
        server = _format_server(
            share_link.get("server")
        )

        port = _parse_port(
            share_link.get("port")
        )

        if not server or port is None:
            return None

        username = str(
            share_link.get(
                "username",
                "",
            )
            or ""
        )

        password = str(
            share_link.get(
                "password",
                "",
            )
            or ""
        )

        if username:
            authority = (
                f"{username}:{password}@"
                f"{server}:{port}"
            )
        else:
            authority = (
                f"{server}:{port}"
            )

        base_link = base64.b64encode(
            authority.encode(
                "utf-8"
            )
        ).decode("ascii")

        link = (
            f"socks://"
            f"{base_link}"
        )

        name = share_link.get(
            "name"
        )

        if name:
            link += (
                "#"
                + _quote_uri(name)
            )

        return link

    # ============================================================
    # AnyTLS
    # ============================================================
    elif node_type == "anytls":
        server = _format_server(
            share_link.get("server")
        )

        port = _parse_port(
            share_link.get("port")
        )

        password = str(
            share_link.get(
                "password",
                "",
            )
            or ""
        )

        if (
            not server
            or port is None
            or not password
        ):
            return None

        params = {}

        idle_check = share_link.get(
            "idle-session-check-interval"
        )

        if idle_check not in (
            None,
            "",
        ):
            params[
                "idleSessionCheckInterval"
            ] = str(idle_check)

        idle_timeout = share_link.get(
            "idle-session-timeout"
        )

        if idle_timeout not in (
            None,
            "",
        ):
            params[
                "idleSessionTimeout"
            ] = str(idle_timeout)

        min_idle = share_link.get(
            "min-idle-session"
        )

        if min_idle not in (
            None,
            "",
        ):
            params[
                "minIdleSession"
            ] = str(min_idle)

        alpn = _format_alpn(
            share_link.get("alpn")
        )

        if alpn:
            params["alpn"] = alpn

        fp = share_link.get(
            "client-fingerprint"
        )

        if fp:
            params["fp"] = str(fp)

        if _is_true(
            share_link.get(
                "skip-cert-verify"
            )
        ):
            params[
                "insecure"
            ] = "1"

        sni = share_link.get(
            "sni"
        )

        if sni:
            params[
                "peer"
            ] = str(sni)

        query_string = urlencode(
            params,
            doseq=True,
        )

        link = (
            f"anytls://"
            f"{_quote_uri(password)}@"
            f"{server}:{port}"
        )

        if query_string:
            link += (
                f"?{query_string}"
            )

        link += (
            "#"
            + _quote_uri(
                share_link.get(
                    "name",
                    "",
                )
            )
        )

        return link

    # ============================================================
    # Unsupported
    # ============================================================
    return None
