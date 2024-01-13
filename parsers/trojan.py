import tool,json,re,urllib,sys
from urllib.parse import urlparse, parse_qs, unquote
def parse(data):
    info = data[:]
    server_info = urlparse(info)
    if server_info.path:
      server_info = server_info._replace(netloc=server_info.netloc + server_info.path, path="")
    if '@' in server_info.netloc:
        _netloc = server_info.netloc.split("@")
    else:
        return None
    netquery = dict(
        (k, v if len(v) > 1 else v[0])
        for k, v in parse_qs(server_info.query).items()
    )
    node = {
        'tag': unquote(server_info.fragment) or tool.genName()+'_trojan',
        'type': 'trojan',
        'server': re.sub(r"\[|\]", "", _netloc[1].rsplit(":", 1)[0]),
        'server_port': int(_netloc[1].rsplit(":", 1)[1].split("/")[0]),
        'password': _netloc[0],
        'tls': {
            'enabled': True,
            'insecure': True
        }
    }
    if netquery.get('allowInsecure') and netquery['allowInsecure'] == '0' :
        node['tls']['insecure'] = False
    if netquery.get('alpn'):
        node['tls']['alpn'] = netquery.get('alpn').strip('{}').split(',')
    if netquery.get('sni'):
        node['tls']['server_name'] = netquery.get('sni', '')
    if netquery.get('fp'):
        node['tls']['utls'] = {
            'enabled': True,
            'fingerprint': netquery.get('fp')
        }
    if netquery.get('type'):
        if netquery['type'] == 'h2':
            node['transport'] = {
                'type':'http',
                'host':netquery.get('host', node['server']),
                'path':netquery.get('path', '/')
            }
        if netquery['type'] == 'ws':
            if netquery.get('host'):
                node['transport'] = {
                     'type':'ws',
                     'path':netquery.get('path', '/'),
                     'headers': {
                         'Host': netquery.get('host')
                    }
                }
        if netquery['type'] == 'grpc':
            node['transport'] = {
                'type':'grpc',
                'service_name':netquery.get('serviceName', '')
            }
    if netquery.get('protocol'):
        node['multiplex'] = {
            'enabled': True,
            'protocol': netquery['protocol']
        }
        if netquery.get('max-streams'):
            node['multiplex']['max_streams'] = int(netquery['max-streams'])
        else:
            node['multiplex']['max_connections'] = int(netquery['max-connections'])
            node['multiplex']['min_streams'] = int(netquery['min-streams'])
        if netquery.get('padding') == 'True':
            node['multiplex']['padding'] = True
    return node