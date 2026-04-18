import tool, re
from urllib.parse import urlparse, parse_qs, unquote

def parse(data):
    info = data[:]
    server_info = urlparse(info)
    try:
        netloc = tool.b64Decode(server_info.netloc).decode('utf-8')
    except:
        netloc = server_info.netloc
    _netloc = netloc.split("@")
    try:
        _netloc_parts = _netloc[1].rsplit(":", 1)
    except:
        return None
    if _netloc_parts[1].isdigit(): 
        server = re.sub(r"\[|\]", "", _netloc_parts[0])
        server_port = int(_netloc_parts[1])
    else:
        return None
        
    netquery = dict(
        (k, v if len(v) > 1 else v[0])
        for k, v in parse_qs(server_info.query).items()
    )
    remarks = netquery.get('remarks', server_info.fragment)
    
    node = {
        'tag': unquote(remarks) or tool.genName()+'_vless',
        'type': 'vless',
        'server': server,
        'server_port': server_port,
        'uuid': _netloc[0].split(':', 1)[-1],
        'packet_encoding': netquery.get('packetEncoding', 'xudp')
    }
    
    if netquery.get('flow'):
        node['flow'] = 'xtls-rprx-vision'
        
    if netquery.get('security', '') not in ['None', 'none', ''] or netquery.get('tls') == '1':
        node['tls'] = {
            'enabled': True,
            'insecure': False,
            'server_name': ''
        }
        if netquery.get('allowInsecure') == '1':
            node['tls']['insecure'] = True
            
        node['tls']['server_name'] = netquery.get('sni', netquery.get('peer', ''))
        if node['tls']['server_name'] == 'None':
            node['tls']['server_name'] = ''
            
        if netquery.get('security') == 'reality' or netquery.get('pbk'): 
            node['tls']['reality'] = {
                'enabled': True,
                'public_key': netquery.get('pbk'),
            }
            sid = netquery.get('sid')
            if isinstance(sid, str) and sid.strip().lower() != "none":
                node['tls']['reality']['short_id'] = netquery['sid']
                
            node['tls']['utls'] = {'enabled': True}
            if netquery.get('fp'):
                node['tls']['utls']['fingerprint'] = netquery['fp']
                
    if netquery.get('type'):
        if netquery['type'] in ['http', 'h2']:
            node['transport'] = {'type': 'http'}
            host_val = netquery.get('host')
            if host_val:
                node['transport']['host'] = host_val.split(',') if isinstance(host_val, str) else host_val
            if netquery.get('path'):
                node['transport']['path'] = netquery.get('path')
                
        elif netquery['type'] == 'ws':
            matches = re.search(r'\?ed=(\d+)$', netquery.get('path', '/'))
            node['transport'] = {
                'type': 'ws',
                "path": netquery.get('path', '/').rsplit("?ed=", 1)[0] if matches else netquery.get('path', '/')
            }
            
            host_val = netquery.get('host', netquery.get('sni', ''))
            if host_val and host_val != 'None':
                node['transport']['headers'] = {"Host": host_val}
                if node.get('tls') and not node['tls']['server_name']:
                    node['tls']['server_name'] = host_val
                    
            if matches:
                node['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol'
                node['transport']['max_early_data'] = int(netquery.get('path', '/').rsplit("?ed=", 1)[1])
                
        elif netquery['type'] == 'grpc':
            node['transport'] = {
                'type': 'grpc',
                'service_name': netquery.get('serviceName', '')
            }
            
    elif netquery.get('obfs') == 'websocket':  
        matches = re.search(r'\?ed=(\d+)$', netquery.get('path', '/'))
        node['transport'] = {
            'type': 'ws',
            "path": netquery.get('path', '/').rsplit("?ed=", 1)[0] if matches else netquery.get('path', '/')
        }
        host_val = netquery.get('peer', netquery.get('obfsParam', netquery.get('sni', '')))
        if host_val and host_val != 'None':
            node['transport']['headers'] = {"Host": host_val}
            if node.get('tls') and not node['tls']['server_name']:
                node['tls']['server_name'] = host_val
                
        if matches:
            node['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol'
            node['transport']['max_early_data'] = int(netquery.get('path', '/').rsplit("?ed=", 1)[1])
            
    if netquery.get('protocol') in ['smux', 'yamux', 'h2mux']:
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
            
    # 清理空的 server_name
    if node.get('tls') and not node['tls'].get('server_name'):
        del node['tls']['server_name']
        
    return node
