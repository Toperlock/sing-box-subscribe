import tool,re
from urllib.parse import urlparse, parse_qs, unquote

def parse(data):
    info = data[:]
    server_info = urlparse(info)
    netquery = dict(
        (k, v if len(v) > 1 else v[0])
        for k, v in parse_qs(server_info.query).items()
    )
    if server_info.path:
        server_info = server_info._replace(netloc=server_info.netloc + server_info.path, path="")
    
    # 尝试匹配官方 URI 规范中的逗号分隔端口 (如 server:21581,21400-21599)
    ports_match = re.search(r',(\d+-\d+)', server_info.netloc)
    
    node = {
        'tag': unquote(server_info.fragment) or tool.genName()+'_hysteria2',
        'type': 'hysteria2',
        'server': re.sub(r"\[|\]", "", server_info.netloc.split("@")[-1].rsplit(":", 1)[0]),
        'server_port': int(re.search(r'\d+', server_info.netloc.rsplit(":", 1)[-1].split(",")[0]).group()),
        "password": netquery['auth'] if netquery.get('auth') else server_info.netloc.split("@")[0].rsplit(":", 1)[-1],
        'tls': {
            'enabled': True,
            'server_name': netquery.get('sni', netquery.get('peer', '')),
            'insecure': False
        }
    }
    
    # 【核心修复区】：双链路多端口兼容与数据清洗
    # 优先读取官方规范的逗号分隔端口
    if netquery.get('upmbps'):
        up_match = re.search(r'\d+', str(netquery['upmbps']))
        if up_match: 
            node['up_mbps'] = int(up_match.group())
            
    if netquery.get('downmbps'):
        down_match = re.search(r'\d+', str(netquery['downmbps']))
        if down_match: 
            node['down_mbps'] = int(down_match.group())
			
    if ports_match:
        node['server_ports'] = [ports_match.group(1).replace('-', ':')]
        if 'server_port' in node:
            del node['server_port']
    # 兜底读取社区泛用的 mport 查询参数 (承接 clash2base64 的输出)
    elif netquery.get('mport'):
        node['server_ports'] = [str(netquery['mport']).replace('-', ':')]
        if 'server_port' in node:
            del node['server_port']
            
    if netquery.get('insecure') in ['1', 'true'] or netquery.get('allowInsecure') == '1':
        node['tls']['insecure'] = True
    if not node['tls'].get('server_name'):
        del node['tls']['server_name']
        node['tls']['insecure'] = True
    elif node['tls']['server_name'] == 'None':
        del node['tls']['server_name']
        
    node['tls']['alpn'] = (netquery.get('alpn') or "h3").strip('{}').split(',')
    
    if netquery.get('obfs', '') not in ['none', '']:
        node['obfs'] = {
            'type': netquery['obfs'],
            'password': netquery['obfs-password'],
        }
        
    return node
