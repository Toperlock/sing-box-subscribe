import tool
import re
from urllib.parse import urlparse, parse_qs, unquote

def parse(data):
    info = data[:]
    server_info = urlparse(info)
    netquery = {
        k: v if len(v) > 1 else v[0]
        for k, v in parse_qs(server_info.query).items()
    }
    if server_info.path:
        server_info = server_info._replace(netloc=server_info.netloc + server_info.path, path="")
    node = {
        'tag': unquote(server_info.fragment) or tool.genName() + '_hysteria2',
        'type': 'hysteria2',
        'server': re.sub(r"\[|\]", "", server_info.netloc.split("@")[-1].rsplit(":", 1)[0]),
        "password": netquery.get('auth') or server_info.netloc.split("@")[0].rsplit(":", 1)[-1],
        'tls': {
            'enabled': True,
            'server_name': netquery.get('sni', netquery.get('peer', '')),
            'insecure': False
        }
    }
    ports_match = re.search(r',(\d{1,5})-(\d{1,5})', server_info.netloc)
    mport_match = None
    if not ports_match and 'mport' in netquery:
        m = re.match(r'(\d{1,5})-(\d{1,5})', str(netquery['mport']))
        if m:
            mport_match = m
    if ports_match or mport_match:
        start_port = int((ports_match or mport_match).group(1))
        end_port = int((ports_match or mport_match).group(2))
        if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
            node['server_ports'] = [f"{start_port}:{end_port}"]
    else:
        port_match = re.search(r'\d{1,5}', server_info.netloc.rsplit(":", 1)[-1].split(",")[0])
        if port_match:
            port = int(port_match.group())
            if 1 <= port <= 65535:
                node['server_port'] = port
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