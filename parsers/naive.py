import tool
import re
from urllib.parse import urlparse, parse_qs, unquote

def parse(data):
    if not data.startswith("naive+https://"):
        return None
    info = data[len("naive+https://"):]
    server_info = urlparse("https://" + info)
    netquery = {
        k: v[0] if len(v) == 1 else v
        for k, v in parse_qs(server_info.query).items()
    }
    node = {
        'tag': unquote(server_info.fragment or 'default_naive'),
        'type': 'naive',
        'server': server_info.hostname,
        'server_port': server_info.port or 443,
        'username': unquote(server_info.username or ''),
        'password': server_info.password or '',
        'tls': {
            'enabled': True,
            'insecure': 'insecure-concurrency' in netquery or netquery.get('insecure') in ['1', 'true'],
            'server_name': netquery.get('sni', ''),
            'alpn': ['http/1.1']
        }
    }
    if not node['tls']['server_name']:
        node['tls'].pop('server_name')
        node['tls']['insecure'] = True
    if 'extra-headers' in netquery:
        headers_str = netquery['extra-headers']
        headers = {}
        for part in headers_str.split(';'):
            if '=' in part:
                k, v = part.split('=', 1)
                headers[k.strip()] = v.strip()
        if headers:
            node['headers'] = headers
    if netquery.get('uot') in ['1', 'true'] or netquery.get('udp_over_tcp') in ['1', 'true']:
        node['udp_over_tcp'] = {
            'enabled': True,
            'version': 2
        }
    return node