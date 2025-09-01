import re

def set_gh_proxy(config, selected_index=0):


    # 加速服务列表（名称, 前缀）
    proxy_methods = [
        ("gh-proxy.com", "https://gh-proxy.com/"),
        ("gh.sageer.me", "https://gh.sageer.me/"),
        ("ghproxy.com", "https://ghproxy.com/"),
        ("mirror.ghproxy.com", "https://mirror.ghproxy.com/"),
        ("jsDelivr", "jsdelivr"),
        ("jsDelivr CF", "testingcf.jsdelivr.net")
    ]

    # 所有 http 代理前缀
    #all_prefixes = [prefix for _, prefix in proxy_methods if not prefix.startswith("jsdelivr") and not prefix.startswith("testingcf")]
    selected_name, selected_prefix = proxy_methods[selected_index]
    all_prefixes = [prefix for _, prefix in proxy_methods]

    def restore_raw_url(line):
        # 识别 jsDelivr 或 CF 镜像，转回 raw.githubusercontent.com
        jsdelivr_pattern = r'https://(?:cdn\.jsdelivr\.net|testingcf\.jsdelivr\.net)/gh/([^/]+)/([^@]+)@([^/]+)/(.*)'
        match = re.match(jsdelivr_pattern, line)
        if match:
            
            user, repo, branch, path = match.groups()
            return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"

        # 识别其他加速前缀
        for prefix in all_prefixes:
            if line.startswith(prefix):
                if selected_prefix in ("jsdelivr", "testingcf.jsdelivr.net") and "raw.githubusercontent.com" not in line:
                    return line
                return line.replace(prefix, selected_prefix, 1)
        return line

    def convert_to_jsdelivr(raw_url, domain="cdn.jsdelivr.net"):
        match = re.match(r'https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)', raw_url)
        if match:
            user, repo, branch, path = match.groups()
            return f"https://{domain}/gh/{user}/{repo}@{branch}/{path}"
        return raw_url

    def apply_proxy(line):
        original = restore_raw_url(line)

        if selected_prefix in ("jsdelivr", "testingcf.jsdelivr.net"):
            # 检查是否是 raw 格式
            if "raw.githubusercontent.com" not in original:
                # print(f"⚠️  无法对非 raw.github 链接使用 jsDelivr 加速，已保留原始链接:\n  {original}")
                return original
            domain = "cdn.jsdelivr.net" if selected_prefix == "jsdelivr" else "testingcf.jsdelivr.net"
            return convert_to_jsdelivr(original, domain=domain)
        else:
            return re.sub(
                r'^https://raw\.githubusercontent\.com/',
                selected_prefix + 'raw.githubusercontent.com/',
                original
            )

    if isinstance(config, str):
        return apply_proxy(config)
    elif isinstance(config, list):
        return [apply_proxy(line) for line in config]
    else:
        raise TypeError("config 应该是字符串或字符串列表")