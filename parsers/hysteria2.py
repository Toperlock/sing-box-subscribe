import tool, re
from urllib.parse import urlparse, parse_qs, unquote

def parse(data):
    info = data[:]
    server_info = urlparse(info)
    netquery = {
        k: v if len(v) > 1 else v[0]
        for k, v in parse_qs(server_info.query).items()
    }

    if server_info.path:
        server_info = server_info._replace(
            netloc=server_info.netloc + server_info.path,
            path=""
        )
    port_str = server_info.netloc.rsplit(":", 1)[-1].split(",")[0]
    port_ranges = re.split(r',', port_str)

    server_host = re.sub(r"\[|\]", "", server_info.netloc.split("@")[-1].rsplit(":", 1)[0])

    node = {
        'tag': unquote(server_info.fragment) or tool.genName() + '_hysteria2',
        'type': 'hysteria2',
        'server': server_host,
        'password': netquery.get('auth') or server_info.netloc.split("@")[0].rsplit(":", 1)[-1],
        'tls': {
            'enabled': True,
            'server_name': netquery.get('sni', netquery.get('peer', '')),
            'insecure': False
        }
    }

    valid_ports = []

    for part in port_ranges:
        if '-' in part:
            start, end = part.split('-', 1)
            if start.isdigit() and end.isdigit():
                start, end = int(start), int(end)
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    valid_ports.append(f"{start}:{end}")
        elif part.isdigit():
            port = int(part)
            if 1 <= port <= 65535:
                valid_ports.append(str(port))

    if len(valid_ports) == 1 and ':' not in valid_ports[0]:
        node['server_port'] = int(valid_ports[0])
    elif valid_ports:
        node['server_ports'] = valid_ports

    if netquery.get('insecure') in ['1', 'true'] or netquery.get('allowInsecure') == '1':
        node['tls']['insecure'] = True

    if not node['tls'].get('server_name') or node['tls']['server_name'] == 'None':
        node['tls'].pop('server_name', None)
        node['tls']['insecure'] = True

    node['tls']['alpn'] = (netquery.get('alpn') or "h3").strip('{}').split(',')

    if netquery.get('obfs') not in ['none', '', None]:
        node['obfs'] = {
            'type': netquery['obfs'],
            'password': netquery.get('obfs-password', '')
        }

    return node