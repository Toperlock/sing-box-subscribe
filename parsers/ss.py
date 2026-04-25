import tool, json, re, urllib
from urllib.parse import parse_qs

def parse(data):
    param = data[5:]
    if not param or param.isspace():
        return None
    node = {
        'tag': tool.genName() + '_shadowsocks',
        'type': 'shadowsocks',
        'server': None,
        'server_port': 0,
        'method': None,
        'password': None
    }
    flag = 0
    # 替换原有的 if param.find('uot') > -1: 逻辑
    query_part = param.split('?')[1].lower() if '?' in param else ''
    if 'uot=1' in query_part or 'uot=true' in query_part:
        node["udp_over_tcp"] = {
            'enabled': True,
            'version': 2
        }
    if param.find('#') > -1:
        if param[param.find('#') + 1:] != '':
            remark = urllib.parse.unquote(param[param.find('#') + 1:])
            node['tag'] = remark
        param = param[:param.find('#')]
    elif param.find('?remarks=') > -1:
        if param[param.find('?remarks=') + 9:] != '':
            remark = urllib.parse.unquote(param[param.find('?remarks=') + 9:])
            node['tag'] = remark
        param = param[:param.find('?remarks=')]
        
    if param.find('plugin=obfs-local') > -1 or param.find('plugin=simple-obfs') > -1:
        if param.find('&', param.find('plugin')) > -1:
            plugin = urllib.parse.unquote(param[param.find('plugin'):param.find('&', param.find('plugin'))])
        else:
            plugin = urllib.parse.unquote(param[param.find('plugin'):])
        param = param[:param.find('?')]
        node['plugin'] = 'obfs-local'
        items = plugin.split(';')
        plugin_dict = {item.split('=')[0]: item.split('=')[1] for item in items if '=' in item}
        result_str = "obfs={};{}".format(
            plugin_dict.get("obfs", ''),
            'obfs-host={};'.format(plugin_dict["obfs-host"]) if plugin_dict.get("obfs-host") else ''
        )
        node['plugin_opts'] = result_str
        
    elif param.find('v2ray-plugin') > -1:
        if param.find('&', param.find('v2ray-plugin')) > -1:
            plugin_raw = param[param.find('v2ray-plugin')+13:param.find('&', param.find('v2ray-plugin'))]
        else:
            plugin_raw = param[param.find('v2ray-plugin')+13:]
            
        try:
            plugin_str = tool.b64Decode(plugin_raw).decode('utf-8')
            # 如果是 JSON 格式，直接解析
            if plugin_str.startswith('{'):
                plugin_dict = json.loads(plugin_str)
            else:
                pairs = [pair.split('=') for pair in plugin_str.split(';') if '=' in pair and pair.count('=') == 1]
                plugin_dict = {key: value for key, value in pairs}
        except:
            plugin_str = urllib.parse.unquote(plugin_raw.lstrip('='))
            pairs = [pair.split('=') for pair in plugin_str.split(';') if '=' in pair and pair.count('=') == 1]
            plugin_dict = {key: value for key, value in pairs}
            
        param = param[:param.find('?')]
        node['plugin'] = 'v2ray-plugin'
        
        result_str = "mode={};{}{}{}{}{}{}{}".format(
            plugin_dict.get("mode", ''),
            'host={};'.format(plugin_dict["host"]) if plugin_dict.get("host") else '',
            'path={};'.format(plugin_dict["path"]) if plugin_dict.get("path") else '',
            'mux={};'.format(plugin_dict["mux"]) if str(plugin_dict.get("mux")).lower() in ['1', 'true'] else '',
            'headers={};'.format(json.dumps(plugin_dict["headers"])) if plugin_dict.get("headers") else '',
            'fingerprint={};'.format(plugin_dict["fingerprint"]) if plugin_dict.get("fingerprint") else '',
            'skip-cert-verify={};'.format('true') if str(plugin_dict.get("skip-cert-verify")).lower() in ['1', 'true'] else '',
            '{};'.format('tls') if str(plugin_dict.get("tls")).lower() in ['1', 'true'] else '',
        )
        node['plugin_opts'] = result_str
        
    if data[5:].find('protocol') > -1:
        smux = data[5:][data[5:].find('protocol'):]
        smux_dict = parse_qs(smux.split('#')[0])
        smux_dict = {k: v[0] for k, v in smux_dict.items() if v[0]}
        node['multiplex'] = {
            'enabled': True,
            'protocol': smux_dict['protocol']
        }
        if smux_dict.get('max-streams'):
            node['multiplex']['max_streams'] = int(smux_dict['max-streams'])
        else:
            node['multiplex']['max_connections'] = int(smux_dict['max-connections'])
            node['multiplex']['min_streams'] = int(smux_dict['min-streams'])
        if smux_dict.get('padding') == 'True':
            node['multiplex']['padding'] = True
            
    try: 
        param = param.split('?')[0]
        matcher = tool.b64Decode(param) 
    except:
        param = param.split('/')[0].split('?')[0] 
        
    if param.find('@') > -1:
        matcher = re.match(r'(.*?)@(.*):(.*)', param)
        if matcher:
            param = matcher.group(1)
            node['server'] = matcher.group(2)
            node['server_port'] = matcher.group(3).split('&')[0]
        else:
            return None
        try:
          matcher = re.match(r'(.*?):(.*)', tool.b64Decode(param).decode('utf-8'))
          if matcher:
              node['method'] = matcher.group(1)
              node['password'] = matcher.group(2)
          else:
              return None
        except:
          matcher = re.match(r'(.*?):(.*)', param)
          if matcher:
              node['method'] = matcher.group(1)
              node['password'] = matcher.group(2)
          else:
              return None
    else:
        matcher = re.match(r'(.*?):(.*)@(.*):(.*)', tool.b64Decode(param).decode('utf-8'))
        if matcher:
            node['method'] = matcher.group(1)
            node['password'] = matcher.group(2)
            node['server'] = matcher.group(3)
            node['server_port'] = matcher.group(4).split('&')[0]
        else:
            return None
            
    node['server_port'] = int(re.search(r'\d+', node['server_port']).group())
    param2 = data[5:]
    
    if param2.find('shadow-tls') > -1:
        flag = 1
        if param2.find('&', param2.find('shadow-tls')) > -1:
            plugin_str = tool.b64Decode(param2[param2.find('shadow-tls')+11:param2.find('&', param2.find('shadow-tls'))].split('#')[0]).decode('utf-8')
        else:
            plugin_str = tool.b64Decode(param2[param2.find('shadow-tls')+11:].split('#')[0]).decode('utf-8')
            
        # 安全解析 JSON，弃用 eval
        try:
            plugin_dict = json.loads(plugin_str)
        except:
            return None
            
        node['detour'] = node['tag']+'_shadowtls'
        node_tls = {
            'tag': node['detour'],
            'type': 'shadowtls',
            'server': node['server'],
            'server_port': node['server_port'],
            'version': int(plugin_dict.get('version', '1')),
            'password': plugin_dict.get('password', ''),
            'tls': {
                'enabled': True,
                'server_name': plugin_dict.get('host', '')
            }
        }
        if plugin_dict.get('address'):
            node_tls['server'] = plugin_dict['address']
        if plugin_dict.get('port'):
            node_tls['server_port'] = int(plugin_dict['port'])
        if plugin_dict.get('fp'):
            node_tls['tls']['utls']={
                'enabled': True,
                'fingerprint': plugin_dict.get('fp')
            }
        del node['server']
        del node['server_port']
        
    if node['method'] == 'chacha20-poly1305':
        node['method'] = 'chacha20-ietf-poly1305'
    elif node['method'] == 'xchacha20-poly1305':
        node['method'] = 'xchacha20-ietf-poly1305'
        
    if flag:
        return node,node_tls
    else:
        return node
