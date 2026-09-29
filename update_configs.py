import json
import base64
import yaml
import re
import urllib.request
from urllib.parse import quote

NEW_NAME = "موز🍌"

def rename_uri(uri, new_name="خیار🥒"):
    """Rename the fragment (name) part of a proxy URI to new_name"""
    try:
        if '#' in uri:
            base, old_name = uri.rsplit('#', 1)
            return f"{base}#{quote(new_name)}"
        else:
            return f"{uri}#{quote(new_name)}"
    except Exception:
        return uri

def rename_all(links):
    """Rename all URIs in a list"""
    return [rename_uri(link) for link in links]

def json_to_uri(config, new_name="خیار🥒"):
    outbound = None
    for ob in config.get('outbounds', []):
        if ob.get('protocol') in ['vless', 'trojan', 'vmess', 'shadowsocks', 'ss']:
            outbound = ob
            break
    if not outbound:
        return None
    
    protocol = outbound['protocol']
    settings = outbound['settings']
    stream = outbound.get('streamSettings', {})
    
    if protocol == 'vless':
        vnext = settings.get('vnext', [{}])[0]
        address = vnext.get('address', '')
        port = vnext.get('port', 443)
        users = vnext.get('users', [{}])
        user = users[0] if users else {}
        uuid = user.get('id', '')
        encryption = user.get('encryption', 'none')
        
        network = stream.get('network', 'tcp')
        security = stream.get('security', 'none')
        ws_settings = stream.get('wsSettings', {})
        tls_settings = stream.get('tlsSettings', {})
        sockopt = stream.get('sockopt', {})
        
        host = ws_settings.get('host', address)
        path = ws_settings.get('path', '/')
        sni = tls_settings.get('serverName', host)
        fp = tls_settings.get('fingerprint', 'chrome')
        alpn = ','.join(tls_settings.get('alpn', ['h2', 'http/1.1']))
        
        query_parts = [
            f'encryption={encryption}',
            f'security={security}',
            f'type={network}',
        ]
        
        if network == 'ws':
            query_parts.append(f'host={quote(host)}')
            query_parts.append(f'path={quote(path)}')
        
        query_parts.append(f'sni={quote(sni)}')
        query_parts.append(f'fp={fp}')
        query_parts.append(f'alpn={quote(alpn)}')
        
        if sockopt:
            query_parts.append(f'sockopt={quote(json.dumps(sockopt, separators=(",", ":")))}')
        
        uri = f"vless://{uuid}@{address}:{port}?{'&'.join(query_parts)}#{quote(new_name)}"
        return uri
    
    elif protocol == 'trojan':
        vnext = settings.get('vnext', [{}])[0]
        address = vnext.get('address', '')
        port = vnext.get('port', 443)
        users = vnext.get('users', [{}])
        user = users[0] if users else {}
        password = user.get('password', '')
        
        network = stream.get('network', 'tcp')
        security = stream.get('security', 'tls')
        ws_settings = stream.get('wsSettings', {})
        tls_settings = stream.get('tlsSettings', {})
        sockopt = stream.get('sockopt', {})
        
        host = ws_settings.get('host', address)
        path = ws_settings.get('path', '/')
        sni = tls_settings.get('serverName', host)
        fp = tls_settings.get('fingerprint', 'chrome')
        alpn = ','.join(tls_settings.get('alpn', ['h2', 'http/1.1']))
        
        query_parts = [
            f'security={security}',
            f'type={network}',
        ]
        
        if network == 'ws':
            query_parts.append(f'host={quote(host)}')
            query_parts.append(f'path={quote(path)}')
        
        query_parts.append(f'sni={quote(sni)}')
        query_parts.append(f'fp={fp}')
        query_parts.append(f'alpn={quote(alpn)}')
        
        if sockopt:
            query_parts.append(f'sockopt={quote(json.dumps(sockopt, separators=(",", ":")))}')
        
        uri = f"trojan://{password}@{address}:{port}?{'&'.join(query_parts)}#{quote(new_name)}"
        return uri
    
    return None

def whitedns_to_uri(proxy, new_name="خیار🥒"):
    proto = proxy.get('type', '')
    name = proxy.get('name', new_name)
    server = proxy.get('server', '')
    port = proxy.get('port', '')
    
    if proto == 'vless':
        uuid = proxy.get('uuid', '')
        network = proxy.get('network', 'tcp')
        tls = proxy.get('tls', False)
        ws_opts = proxy.get('ws-opts', {})
        ws_path = ws_opts.get('path', '/')
        ws_headers = ws_opts.get('headers', {})
        ws_host = ws_headers.get('Host', server)
        if isinstance(ws_host, list): ws_host = ws_host[0]
        
        sni = proxy.get('servername', ws_host)
        alpn = proxy.get('alpn', ['h2', 'http/1.1'])
        alpn_str = ','.join(alpn) if isinstance(alpn, list) else alpn
        fp = proxy.get('client-fingerprint', 'chrome')
        
        query_parts = [
            'encryption=none',
            f'type={network}',
            f'security={"tls" if tls else "none"}',
        ]
        
        if network == 'ws':
            query_parts.append(f'host={quote(ws_host)}')
            query_parts.append(f'path={quote(ws_path)}')
        
        query_parts.append(f'sni={quote(sni)}')
        query_parts.append(f'fp={fp}')
        query_parts.append(f'alpn={quote(alpn_str)}')
        
        uri = f"vless://{uuid}@{server}:{port}?{'&'.join(query_parts)}#{quote(new_name)}"
        return uri
    
    elif proto == 'trojan':
        password = proxy.get('password', '')
        network = proxy.get('network', 'tcp')
        tls = proxy.get('tls', True)
        ws_opts = proxy.get('ws-opts', {})
        ws_path = ws_opts.get('path', '/')
        ws_headers = ws_opts.get('headers', {})
        ws_host = ws_headers.get('Host', server)
        if isinstance(ws_host, list): ws_host = ws_host[0]
        
        sni = proxy.get('sni', ws_host)
        alpn = proxy.get('alpn', ['h2', 'http/1.1'])
        alpn_str = ','.join(alpn) if isinstance(alpn, list) else alpn
        fp = proxy.get('client-fingerprint', 'chrome')
        
        query_parts = [
            f'type={network}',
            f'security={"tls" if tls else "none"}',
        ]
        
        if network == 'ws':
            query_parts.append(f'host={quote(ws_host)}')
            query_parts.append(f'path={quote(ws_path)}')
        
        query_parts.append(f'sni={quote(sni)}')
        query_parts.append(f'fp={fp}')
        query_parts.append(f'alpn={quote(alpn_str)}')
        
        uri = f"trojan://{password}@{server}:{port}?{'&'.join(query_parts)}#{quote(new_name)}"
        return uri
    
    elif proto == 'vmess':
        uuid = proxy.get('uuid', '')
        network = proxy.get('network', 'tcp')
        tls = proxy.get('tls', False)
        ws_opts = proxy.get('ws-opts', {})
        ws_path = ws_opts.get('path', '/')
        ws_headers = ws_opts.get('headers', {})
        ws_host = ws_headers.get('Host', server)
        if isinstance(ws_host, list): ws_host = ws_host[0]
        
        vmess_config = {
            "v": "2",
            "ps": new_name,
            "add": server,
            "port": str(port),
            "id": uuid,
            "aid": "0",
            "scy": "auto",
            "net": network,
            "type": "none",
            "host": ws_host,
            "path": ws_path,
            "tls": "tls" if tls else "",
            "sni": proxy.get('servername', server),
            "fp": proxy.get('client-fingerprint', 'chrome'),
            "alpn": "h2,http/1.1"
        }
        vmess_b64 = base64.b64encode(json.dumps(vmess_config).encode()).decode()
        return f"vmess://{vmess_b64}"
    
    elif proto == 'ss':
        cipher = proxy.get('cipher', '')
        password = proxy.get('password', '')
        ss_uri = f"{cipher}:{password}@{server}:{port}"
        ss_b64 = base64.b64encode(ss_uri.encode()).decode()
        return f"ss://{ss_b64}#{quote(new_name)}"
    
    return None

def fetch_bpb_normal():
    url = "https://vsix6rg3eolucr0ywl9sc5pkdwnpw55m.pages.dev/1XsTsfMUcBuMc3/sub/normal?app=xray"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    data = json.loads(urllib.request.urlopen(req, timeout=30).read().decode('utf-8'))
    links = []
    for config in data:
        uri = json_to_uri(config)
        if uri:
            links.append(uri)
    return links

def fetch_twilight_hill():
    url = "https://twilight-hill-438b.gotvaram.workers.dev/sync?sub=Masuma"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    b64 = urllib.request.urlopen(req, timeout=30).read().decode('utf-8')
    decoded = base64.b64decode(b64).decode('utf-8')
    links = [line.strip() for line in decoded.strip().split('\n') if line.strip()]
    return links  # Will be renamed later

def fetch_blueknight():
    url = "https://raw.githubusercontent.com/BlueKnightNet/blueknight_net-sub-link/refs/heads/blue-knight-net/BlueKnight.txt"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    text = urllib.request.urlopen(req, timeout=30).read().decode('utf-8')
    links = [line.strip() for line in text.strip().split('\n') if line.strip()]
    return links  # Will be renamed later

def fetch_whitedns():
    url = "https://raw.githubusercontent.com/iampedii/whitedns-sub/refs/heads/main/mihomo.yaml"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    text = urllib.request.urlopen(req, timeout=30).read().decode('utf-8')
    yaml_data = yaml.safe_load(text)
    links = []
    for proxy in yaml_data.get('proxies', []):
        uri = whitedns_to_uri(proxy)
        if uri:
            links.append(uri)
    return links

def fetch_freedom_house():
    url = "https://raw.githubusercontent.com/10ium/free-config/refs/heads/main/free-mihomo-sub/freedom_house_countries__NoRule.yaml"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    text = urllib.request.urlopen(req, timeout=30).read().decode('utf-8')
    freedom_yaml = yaml.safe_load(text)
    
    links = []
    providers = freedom_yaml.get('proxy-providers', {})
    for name, provider in providers.items():
        url = provider.get('url', '')
        if url:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                content = urllib.request.urlopen(req, timeout=30).read().decode('utf-8')
                provider_yaml = yaml.safe_load(content)
                for proxy in provider_yaml.get('proxies', []):
                    uri = whitedns_to_uri(proxy)
                    if uri:
                        links.append(uri)
            except Exception as e:
                print(f"Error fetching {name}: {e}")
    return links

def main():
    all_links = []
    
    # Static sources (fetched once)
    print("Fetching BPB Normal...")
    all_links.extend(fetch_bpb_normal())
    print("Fetching Twilight Hill...")
    all_links.extend(fetch_twilight_hill())
    print("Fetching BlueKnight...")
    all_links.extend(fetch_blueknight())
    print("Fetching WhiteDNS...")
    all_links.extend(fetch_whitedns())
    
    # Dynamic sources (updated every 12 hours)
    print("Fetching Freedom House providers...")
    all_links.extend(fetch_freedom_house())
    
    # Deduplicate FIRST
    seen = set()
    unique_links = []
    for link in all_links:
        if link not in seen:
            seen.add(link)
            unique_links.append(link)
    
    # THEN rename ALL unique links
    print(f"Renaming {len(unique_links)} unique configs...")
    unique_links = [rename_uri(link) for link in unique_links]
    
    print(f"Total unique renamed configs: {len(unique_links)}")
    
    with open('configs.txt', 'w') as f:
        f.write('\n'.join(unique_links))
    
    print("Updated configs.txt")

if __name__ == '__main__':
    main()
