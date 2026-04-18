import tool, re
from urllib.parse import urlparse, parse_qs

def parse(data):
    info = data[:]
    server_info = urlparse(info)
    if server_info.path:
        server_info = server_info._replace(netloc=server_info.netloc + server_info.path)
    _netloc = server_info.netloc.rsplit("@", 1)
    
    netquery = dict(
        (k, v if len(v) > 1 else v[0])
        for k, v in parse_qs(server_info.query).items()
    )
    
    node = {
        'tag': server_info.fragment or tool.genName()+'_tuic',
        'type': 'tuic',
        'server': re.sub(r"\[|\]", "", _netloc[1].rsplit(":", 1)[0]),
        'server_port': int(re.search(r'\d+', _netloc[1].rsplit(":", 1)[1]).group()),
        'uuid': _netloc[0].split(":")[0],
        'password': _netloc[0].split(":")[1] if len(_netloc[0].split(":")) > 1 else netquery.get('password', ''),
        'congestion_control': netquery.get('congestion_control', 'bbr'),
        'udp_relay_mode': netquery.get('udp_relay_mode', 'native'), # 补充默认值
        'zero_rtt_handshake': False,
        'heartbeat': '10s',
        'tls': {
            'enabled': True,
            'alpn': (netquery.get('alpn') or "h3").strip('{}').split(','),
            'insecure': False
        }
    }
    
    # 修正 insecure 匹配逻辑
    if str(netquery.get('allow_insecure')).lower() in ['1', 'true']:
        node['tls']['insecure'] = True
        
    # 精简 SNI 逻辑：除非明确要求 disable_sni=1，否则赋予 SNI
    if str(netquery.get('disable_sni')) != '1':
        sni_val = netquery.get('sni', netquery.get('peer', ''))
        if sni_val:
            node['tls']['server_name'] = sni_val
    # ...原解析逻辑...
    
    # 承接 clash2base64 下发的 mport 多端口参数
    if netquery.get('mport'):
        node['server_ports'] = [str(netquery['mport']).replace('-', ':')]
        if 'server_port' in node:
            del node['server_port']
            
    return node
