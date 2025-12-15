import re
from urllib.parse import parse_qs, unquote, urlparse

from .. import tool
from .base import ParserBase


class Hysteria2Parser(ParserBase):
    def parse(self, data):
        info = data[:]
        server_info = urlparse(info)
        netquery = dict(
            (k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(server_info.query).items()
        )
        if server_info.path:
          server_info = server_info._replace(netloc=server_info.netloc + server_info.path, path="")
        node = {
            'tag': unquote(server_info.fragment) or tool.generate_random_name() + '_hysteria2',
            'type': 'hysteria2',
            'server': re.sub(r"\[|\]", "", server_info.netloc.split("@")[1].rsplit(":", 1)[0]),
            'server_port': int(re.search(r'\d+', server_info.netloc.rsplit(":", 1)[1].split(",")[0]).group()),
            "password": server_info.netloc.split("@")[0].rsplit(":", 1)[-1],
            'up_mbps': int(re.search(r'\d+', netquery.get('upmbps', '10')).group()),
            'down_mbps': int(re.search(r'\d+', netquery.get('downmbps', '100')).group()),
            'tls': {
                'enabled': True,
                'server_name': netquery.get('sni', netquery.get('peer', ''))
            }
        }
        if 'ports' in netquery:
            node['ports'] = netquery['ports']

        if netquery.get('insecure') == '1' or netquery.get('allowInsecure') == '1':
            node['tls']['insecure'] = True
        if node['tls']['server_name'] == '':
            del node['tls']['server_name']
            node['tls']['insecure'] = True
        node['tls']['alpn'] = (netquery.get('alpn') or "h3").strip('{}').split(',')
        if netquery.get('obfs', '') not in ['none', '']:
            node['obfs'] = {
                'type': netquery['obfs'],
                'password': netquery['obfs-password'],
            }
        return (node)
