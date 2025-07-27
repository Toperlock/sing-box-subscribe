import tool
import re
from urllib.parse import urlparse, parse_qs, unquote

def parse(data):
    info = data[:]
    server_info = urlparse(info)
    query_params = parse_qs(server_info.query)
    netquery = {}
    for k, v in query_params.items():
        netquery[k] = v if len(v) > 1 else v[0]
    if server_info.path:
        netloc = server_info.netloc + server_info.path
    else:
        netloc = server_info.netloc
    at_pos = netloc.rfind('@')
    if at_pos != -1:
        userinfo = netloc[:at_pos]
        hostport = netloc[at_pos+1:]
    else:
        userinfo = ''
        hostport = netloc
    colon_pos = hostport.rfind(':')
    if colon_pos != -1:
        host = hostport[:colon_pos]
        port_part = hostport[colon_pos+1:]
    else:
        host = hostport
        port_part = ''
    host = host.replace('[', '').replace(']', '')
    password = netquery.get('auth')
    if not password and userinfo:
        password = userinfo.rsplit(':', 1)[-1]
    tag = unquote(server_info.fragment) if server_info.fragment else tool.genName() + '_hysteria2'
    tls_server_name = netquery.get('sni') or netquery.get('peer') or ''
    tls_insecure = False
    if netquery.get('insecure') in ('1', 'true') or netquery.get('allowInsecure') == '1':
        tls_insecure = True
    if not tls_server_name or tls_server_name == 'None':
        tls_server_name = None
        tls_insecure = True
    node = {
        'tag': tag,
        'type': 'hysteria2',
        'server': host,
        'password': password,
        'tls': {
            'enabled': True,
            'server_name': tls_server_name,
            'insecure': tls_insecure,
            'alpn': (netquery.get('alpn', 'h3').strip('{}').split(','))
        }
    }
    comma_pos = netloc.find(',')
    port_range_str = ''
    if comma_pos != -1:
        port_range_str = netloc[comma_pos+1:]
    if port_range_str:
        parts = port_range_str.split('-', 1)
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            start_port, end_port = int(parts[0]), int(parts[1])
            if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                node['server_ports'] = [f"{start_port}:{end_port}"]
    elif 'mport' in netquery:
        mport = str(netquery['mport'])
        parts = mport.split('-', 1)
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            start_port, end_port = int(parts[0]), int(parts[1])
            if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                node['server_ports'] = [f"{start_port}:{end_port}"]
    else:
        port_str = port_part.split(',')[0]
        if port_str.isdigit():
            port = int(port_str)
            if 1 <= port <= 65535:
                node['server_port'] = port
    obfs = netquery.get('obfs')
    if obfs not in (None, '', 'none'):
        node['obfs'] = {
            'type': obfs,
            'password': netquery.get('obfs-password', '')
        }
    return node