#!/usr/bin/env python3
"""XHTTP-CDN: single-host VLESS/XHTTP + Cloudflare + ECH installer.

No shell interpolation, no API token in command arguments or exports.
Supports fresh Debian 12/13 and Ubuntu 22.04/24.04/26.04/26.10, systemd.
"""
import argparse
import base64
import contextlib
import datetime
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

VERSION = '1.1.3'
XRAY_VERSION = '26.10.21'
ROOT = Path('/etc/xhttp-cdn')
STATE = ROOT / 'state.json'
BIN = Path('/usr/local/lib/xhttp-cdn/xray')
OUT = Path('/root/xhttp-cdn-nodes')
NGINX = Path('/etc/nginx/sites-available/xhttp-cdn')
UFW_FILES = ('/etc/default/ufw', '/etc/ufw/ufw.conf', '/etc/ufw/user.rules', '/etc/ufw/user6.rules')
PRIVATE = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
           '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4',
           '240.0.0.0/4', '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Failure(Exception):
    pass


class APIError(Failure):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def run(*args, capture=False, check=True, timeout=900):
    p = subprocess.run([str(a) for a in args], text=True, encoding='utf-8',
                       errors='replace', capture_output=capture, timeout=timeout)
    if check and p.returncode:
        # Never print command arguments: credentials could be present in future commands.
        raise Failure(f'{Path(str(args[0])).name} 执行失败，退出码 {p.returncode}。请查看上方错误或服务日志。')
    return p.stdout.strip() if capture else p.returncode


def fetch(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=headers or {'User-Agent': 'XHTTP-CDN/' + VERSION})
    with HTTP.open(req, timeout=timeout) as r:
        return r.read()


def write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise Failure(f'拒绝覆盖符号链接：{path}')
    fd, name = tempfile.mkstemp(prefix='.xhttp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data.encode() if isinstance(data, str) else data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def dump(path, obj):
    write(path, json.dumps(obj, ensure_ascii=False, indent=2) + '\n')


def owned_write(s, path, data, mode=0o600):
    raw = data.encode() if isinstance(data, str) else data
    s.setdefault('owned_files', {})[str(path)] = hashlib.sha256(raw).hexdigest()
    dump(STATE, s)  # Write-ahead ownership record; survives interruption after file creation.
    write(path, raw, mode)


def package_names(text):
    return sorted(line.split('\t')[0] for line in text.splitlines()
                  if line.endswith('\tinstalled'))


def installed_packages():
    return package_names(run('dpkg-query', '-W', '-f=${binary:Package}\t${db:Status-Status}\n', capture=True))


def remember_packages(s):
    if 'packages_before' not in s:
        baseline = os.environ.get('XHTTP_CDN_BOOTSTRAP_BASELINE')
        s['packages_before'] = package_names(Path(baseline).read_text()) if baseline else installed_packages()
        s['packages_added'] = sorted(set(installed_packages()) - set(s['packages_before']))
        s['certbot_timer_before'] = {
            'enabled': run('systemctl', 'is-enabled', 'certbot.timer', capture=True, check=False) == 'enabled',
            'active': run('systemctl', 'is-active', 'certbot.timer', capture=True, check=False) == 'active'}
        dump(STATE, s)


def fingerprint(path):
    p = Path(path)
    if p.is_symlink():
        return 'symlink:' + os.readlink(p)
    if p.is_file():
        return hashlib.sha256(p.read_bytes()).hexdigest()
    return None


def tree_fingerprints(path):
    p = Path(path)
    return {str(x): fingerprint(x) for x in p.rglob('*') if x.is_file() or x.is_symlink()} if p.exists() else {}


def domain(value):
    try:
        value = value.strip().rstrip('.').encode('idna').decode().lower()
    except UnicodeError:
        raise Failure('域名格式不正确。') from None
    if len(value) > 253 or '.' not in value or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')
    ):
        raise Failure('请输入合法域名，不含 https://、端口或路径。')
    return value


def confirm_input(label, expected):
    """Normalize confirmation words only; never normalize credential case."""
    return input(label).strip().casefold() == expected.casefold()


def token_input(label):
    v = getpass.getpass(label).strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{20,256}', v):
        raise Failure('Token 格式不正确。请使用 API Token，不是 Global API Key。')
    return v


class CF:
    def __init__(self, token):
        self.token = token

    def api(self, method, path, body=None):
        raw = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request('https://api.cloudflare.com/client/v4' + path,
            data=raw, method=method, headers={'Authorization': 'Bearer ' + self.token,
            'Content-Type': 'application/json', 'User-Agent': 'XHTTP-CDN/' + VERSION})
        # Mutations deliberately not retried: resume re-reads resources after uncertain outcome.
        try:
            with HTTP.open(req, timeout=45) as r:
                result = json.load(r)
        except urllib.error.HTTPError as e:
            raise APIError(e.code, f'Cloudflare {method} {path.split("?")[0]} 返回 HTTP {e.code}；检查 Token 权限、套餐及规则配额。') from None
        if not result.get('success'):
            codes = [x.get('code') for x in result.get('errors', [])]
            raise APIError(400, f'Cloudflare API 失败：{codes}，接口 {path.split("?")[0]}')
        return result['result']


def zone_setup(cf, s):
    zones = cf.api('GET', '/zones?' + urllib.parse.urlencode({'name': s['zone'], 'per_page': 50}))
    if len(zones) > 1:
        raise Failure('找到多个同名区域，请使用限定账户的 Token。')
    if zones:
        z = zones[0]
    else:
        account = input('域名尚未加入 CF。请输入 Cloudflare Account ID（32位）：').strip().lower()
        if not re.fullmatch('[a-fA-F0-9]{32}', account):
            raise Failure('Account ID 不正确。')
        z = cf.api('POST', '/zones', {'name': s['zone'], 'account': {'id': account}, 'type': 'full'})
    s['zone_id'] = z['id']
    dump(STATE, s)
    print('Cloudflare NS：\n  ' + '\n  '.join(z.get('name_servers', [])))
    if z['status'] != 'active':
        print('请到域名注册商修改 NS。等待期间可 Ctrl+C，稍后重新执行继续。')
    deadline = time.monotonic() + 1200
    while z['status'] != 'active':
        if time.monotonic() > deadline:
            raise Failure('20 分钟内域名未激活；NS 传播可能更久，稍后重新执行。')
        time.sleep(15)
        z = cf.api('GET', '/zones/' + z['id'])
        print('域名状态：' + z['status'], flush=True)


def cache_rule(cf, zid, host, state):
    prefix = '/zones/' + zid + '/rulesets'
    phase = 'http_request_cache_settings'
    ref = 'xhttp-cdn_' + hashlib.sha256(host.encode()).hexdigest()[:16]
    rule = {'ref': ref, 'description': 'XHTTP-CDN cache bypass: ' + host,
            'expression': f'(http.host eq "{host}")', 'action': 'set_cache_settings',
            'action_parameters': {'cache': False}, 'enabled': True}
    try:
        rs = cf.api('GET', prefix + '/phases/' + phase + '/entrypoint')
    except APIError as e:
        if e.status != 404:
            raise
        state.setdefault('cache_before', {'rules': []})
        state['cache_started'] = True
        dump(STATE, state)
        cf.api('POST', prefix, {'name': 'XHTTP-CDN cache', 'kind': 'zone',
                              'phase': phase, 'rules': [rule]})
        return
    if 'cache_before' not in state:
        state['cache_before'] = rs
    state['cache_started'] = True
    dump(STATE, state)
    existing = next((r for r in rs.get('rules', []) if r.get('ref') == ref), None)
    # Append/move only our rule; never replace the zone's whole ruleset.
    # Cloudflare rejects moving an already-last rule to the bottom (20011).
    # Keep its position when updating it; new/non-last rules still go last.
    if not existing or existing['id'] != rs['rules'][-1]['id']:
        rule['position'] = {'after': ''}
    if existing:
        cf.api('PATCH', prefix + '/' + rs['id'] + '/rules/' + existing['id'], rule)
    else:
        cf.api('POST', prefix + '/' + rs['id'] + '/rules', rule)


def cloudflare_setup(cf, s):
    base = '/zones/' + s['zone_id']
    records = cf.api('GET', base + '/dns_records?' + urllib.parse.urlencode({'name': s['host'], 'per_page': 100}))
    relevant = [r for r in records if r['type'] in ('A', 'AAAA', 'CNAME')]
    a = [r for r in relevant if r['type'] == 'A']
    if len(relevant) > 1 or (relevant and not a):
        raise Failure('节点名存在多个 A/AAAA 或 CNAME；请先整理该名称的记录，脚本不会删除它们。')
    if a and a[0]['content'] != s['ip'] and not s.get('dns_owned'):
        if not confirm_input(f'{s["host"]} 已指向其他 IP。输入 REPLACE 才替换（不区分大小写）：', 'REPLACE'):
            raise Failure('保留原有 DNS，停止。')
    if 'dns_before' not in s:
        s['dns_before'] = relevant
        dump(STATE, s)
    record = {'type': 'A', 'name': s['host'], 'content': s['ip'], 'ttl': 1, 'proxied': True,
              'comment': 'Managed by XHTTP-CDN installer'}
    cf.api('PATCH' if a else 'POST', base + '/dns_records' + ('/' + a[0]['id'] if a else ''), record)
    s['dns_owned'] = True
    dump(STATE, s)
    wanted = {'ssl': 'strict', 'tls_1_3': 'on', 'http2': 'on'}
    before = s.setdefault('settings_before', {})
    for setting, value in wanted.items():
        current = cf.api('GET', base + '/settings/' + setting)
        if setting not in before:
            before[setting] = current['value']
            dump(STATE, s)
        if current['value'] != value:
            if current.get('editable') is False:
                raise Failure(f'CF 设置 {setting} 不可编辑且不符合要求。')
            cf.api('PATCH', base + '/settings/' + setting, {'value': value})
    # Some free zones do not expose an editable ECH setting. DNS + real handshake are authoritative.
    try:
        ech = cf.api('GET', base + '/settings/ech')
        if ech.get('value') != 'on' and ech.get('editable', False):
            before.setdefault('ech', ech['value'])
            dump(STATE, s)
            cf.api('PATCH', base + '/settings/ech', {'value': 'on'})
    except APIError:
        print('ECH 设置接口不可用；稍后以实际 HTTPS DNS 记录和握手为准。')
    cache_rule(cf, s['zone_id'], s['host'], s)


def server_config(s):
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{
        'listen': '127.0.0.1', 'port': 10000, 'protocol': 'vless',
        'settings': {'clients': [{'id': s['uuid']}], 'decryption': 'none'},
        'streamSettings': {'network': 'xhttp', 'security': 'none',
                           'xhttpSettings': {'path': s['path'], 'mode': 'packet-up'}}}],
        'outbounds': [{'protocol': 'freedom', 'tag': 'direct',
                      'streamSettings': {'sockopt': {'domainStrategy': 'UseIPv4'}}},
                      {'protocol': 'blackhole', 'tag': 'block'}],
        'routing': {'domainStrategy': 'IPOnDemand', 'rules': [
            {'type': 'field', 'ip': PRIVATE, 'outboundTag': 'block'}]}}


def client_config(s, ech=False, port=10808, address=None, remote_port=443):
    tls = {'serverName': s['host'], 'fingerprint': 'chrome', 'alpn': ['h2'], 'allowInsecure': False}
    if ech:
        tls['echConfigList'] = s['doh']
    return {'log': {'loglevel': 'warning'}, 'inbounds': [
        {'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'udp': True}}],
        'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
            'address': address or (s['edge'] if ech else s['host']), 'port': remote_port,
            'users': [{'id': s['uuid'], 'encryption': 'none'}]}]},
            'streamSettings': {'network': 'xhttp', 'security': 'tls', 'tlsSettings': tls,
                'xhttpSettings': {'host': s['host'], 'path': s['path'], 'mode': 'packet-up'}}}]}


def node_uri(s, ech=False):
    q = {'encryption': 'none', 'security': 'tls', 'type': 'xhttp', 'mode': 'packet-up',
         'host': s['host'], 'sni': s['host'], 'path': s['path'], 'fp': 'chrome', 'alpn': 'h2'}
    if ech:
        q['ech'] = s['doh']
    return 'vless://' + s['uuid'] + '@' + (s['edge'] if ech else s['host']) + ':443?' + \
        urllib.parse.urlencode(q, quote_via=urllib.parse.quote) + '#' + urllib.parse.quote(
            'XHTTP-CDN-' + s['host'] + ('-ECH' if ech else '-XHTTP'))


def nginx_config(s):
    host, path = s['host'], s['path']
    return f'''# Managed by XHTTP-CDN {VERSION}
server {{
    listen 443 ssl http2;
    server_name {host};
    ssl_certificate /etc/letsencrypt/live/{host}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{host}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;
    root /var/www/xhttp-cdn;
    location ^~ {path} {{
        client_max_body_size 2m;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_pass http://127.0.0.1:10000;
        access_log off;
    }}
    location / {{ try_files $uri $uri/ =404; }}
}}
'''


def get_networks():
    networks = []
    for family in ('v4', 'v6'):
        lines = fetch('https://www.cloudflare.com/ips-' + family).decode().splitlines()
        if len(lines) < 5:
            raise Failure('Cloudflare IP 网段下载不完整。')
        for line in lines:
            n = ipaddress.ip_network(line.strip())
            if not n.is_global or n.prefixlen < (8 if n.version == 4 else 20):
                raise Failure('Cloudflare IP 网段校验失败。')
            networks.append(str(n))
    return networks


def ssh_ports():
    sshd = shutil.which('sshd') or '/usr/sbin/sshd'
    # OpenSSH versions differ in keyword case ("port" versus "Port").
    # Do not rely on SSH_CONNECTION being preserved by sudo.
    ports = {int(p) for p in re.findall(r'^port (\d+)$', run(sshd, '-T', capture=True), re.M | re.I)}
    if os.environ.get('SSH_CONNECTION'):
        ports.add(int(os.environ['SSH_CONNECTION'].split()[-1]))
    if not ports or any(not 1 <= p <= 65535 for p in ports):
        raise Failure('无法确认 SSH 端口；未修改防火墙。')
    return ports


def ufw_guard():
    # Installing Nginx adds an inert application profile, not an active rule.
    config = {p: digest for p, digest in tree_fingerprints('/etc/ufw').items()
              if 'applications.d' not in Path(p).parts}
    return {**config, '/etc/default/ufw': fingerprint('/etc/default/ufw')}


def audit_basic_ufw():
    """Validate an active, SSH-only UFW baseline before automatic reuse."""
    status = run('ufw', 'status', 'verbose', capture=True)
    if not re.search(r'^Status: active$', status, re.M) or not re.search(
            r'^Default: deny \(incoming\), allow \(outgoing\), (?:disabled|deny) \(routed\)$', status, re.M):
        raise Failure('自动复用只支持已启用、默认拒绝入站/允许出站且不放行转发的基础 UFW。')
    if not re.search(r'^IPV6=yes$', Path('/etc/default/ufw').read_text(), re.M):
        raise Failure('自动复用要求 UFW 已启用 IPv6 管理。')
    ports = ssh_ports()
    added = run('ufw', 'show', 'added', capture=True)
    commands = [line.strip() for line in added.splitlines() if line.strip().startswith('ufw ')]
    expected = {f'ufw allow {p}/tcp' for p in ports}
    if not commands or set(commands) != expected:
        raise Failure('自动复用只接受与实际 SSH 端口一致的 ufw allow PORT/tcp 规则；其他规则需人工审查。')
    # Cross-check the active IPv4/IPv6 rules, not only the persisted rule commands.
    rows = re.split(r'^--\s+[- ]+$', status, maxsplit=1, flags=re.M)
    if len(rows) != 2:
        raise Failure('无法核验 UFW 活动规则表，停止。')
    seen = set()
    for line in rows[1].splitlines():
        if not line.strip():
            continue
        m = re.fullmatch(r'\s*(\d+)/tcp\s+(\(v6\)\s+)?ALLOW IN\s+Anywhere( \(v6\))?\s*', line)
        if not m or bool(m[2]) != bool(m[3]):
            raise Failure('UFW 存在非基础 SSH 活动规则，停止。')
        seen.add((int(m[1]), bool(m[2])))
    if seen != {(p, v6) for p in ports for v6 in (False, True)}:
        raise Failure('UFW 的 IPv4/IPv6 SSH 规则与实际 SSH 端口不一致，停止。')
    return ufw_guard()


def check_firewall_backend(reuse_ufw=False):
    for cmd in ('iptables-save', 'ip6tables-save'):
        if not shutil.which(cmd):
            continue
        raw = run(cmd, capture=True)
        if not reuse_ufw:
            if re.search(r'^-A |^:\S+ (DROP|REJECT)', raw, re.M):
                raise Failure('已有 iptables 防火墙规则，停止以免影响现有服务。')
            continue
        for line in raw.splitlines():
            if not line or line.startswith('#') or line == 'COMMIT':
                continue
            if line == '*filter' or re.fullmatch(r':(?:INPUT|OUTPUT|FORWARD) (?:ACCEPT|DROP) \[\d+:\d+\]', line):
                continue
            if re.fullmatch(r':ufw6?-[\w-]+ - \[\d+:\d+\]', line) or re.match(r'^-A ufw6?-[\w-]+ ', line):
                continue
            if re.fullmatch(r'-A (?:INPUT|OUTPUT|FORWARD) -j ufw6?-[\w-]+', line):
                continue
            raise Failure('检测到 UFW 之外或无法识别的 iptables 规则，不能自动复用。')
    if shutil.which('nft'):
        tables = run('nft', 'list', 'tables', capture=True)
        allowed = {'table ip filter', 'table ip6 filter'} if reuse_ufw else set()
        if any(line.strip() not in allowed for line in tables.splitlines() if line.strip()):
            raise Failure('已有非本安装器支持的 nftables 表，停止以免影响现有服务。')


def preflight(resume, reuse_ufw=False):
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise Failure('请在新 Linux VPS 上以 root 执行。')
    info = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    distro, version = info.get('ID', '').strip('"'), info.get('VERSION_ID', '').strip('"')
    supported = {'ubuntu': ['22.04', '24.04', '26.04', '26.10'], 'debian': ['12', '13']}
    if version not in supported.get(distro, []):
        raise Failure('支持 Debian 12/13、Ubuntu 22.04/24.04/26.04/26.10。')
    if not Path('/run/systemd/system').exists():
        raise Failure('需要正常运行 systemd 的 VPS，不支持普通 Docker 容器。')
    if not resume:
        for p in [ROOT, OUT, Path('/var/www/xhttp-cdn'), Path('/usr/local/etc/xhttp-cdn'),
                  Path('/etc/letsencrypt/renewal-hooks/deploy/xhttp-cdn-nginx'),
                  Path('/etc/nginx'), Path('/usr/local/etc/xray'), BIN.parent,
                  Path('/etc/systemd/system/xhttp-cdn-xray.service')]:
            if p.exists():
                raise Failure(f'检测到已有配置 {p}，本安装器只接管全新主机或自己的安装。')
        listeners = run('ss', '-H', '-ltn', capture=True)
        if re.search(r':(?:80|443|10000)\s', listeners):
            raise Failure('80、443 或 10000 端口已被占用，请使用新主机。')
        active_ufw = bool(shutil.which('ufw') and 'Status: active' in run('ufw', 'status', capture=True))
        if reuse_ufw and not active_ufw:
            raise Failure('--reuse-ufw 要求主机已有启用的 UFW；普通安装请省略此兼容参数。')
        guard = audit_basic_ufw() if active_ufw else None
        check_firewall_backend(active_ufw)
        if active_ufw:
            print('已自动识别并核验基础 SSH UFW，将保留原有规则和默认策略。')
        return guard


def install_xray(s=None):
    if BIN.exists():
        if XRAY_VERSION not in run(BIN, 'version', capture=True):
            raise Failure('已有内核版本与锁定版本不同；请人工检查，不自动升级。')
        return
    arch = {'x86_64': '64', 'aarch64': 'arm64-v8a'}.get(platform.machine())
    if not arch:
        raise Failure('仅支持 x86_64 / aarch64。')
    name = f'Xray-linux-{arch}.zip'
    release = json.loads(fetch('https://api.github.com/repos/XTLS/Xray-core/releases/tags/v' + XRAY_VERSION))
    asset = next(a for a in release['assets'] if a['name'] == name)
    digest = asset.get('digest') or ''
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        checksum = next(a for a in release['assets'] if a['name'] == name + '.dgst')
        checksums = fetch(checksum['browser_download_url']).decode()
        matches = re.findall(r'(?im)^.*(?:SHA256|SHA2-256).*?=\s*([0-9a-f]{64})\s*$', checksums)
        if len(matches) != 1:
            raise Failure('无法读取官方 SHA256 校验值，停止下载。')
        digest = 'sha256:' + matches[0].lower()
    archive = fetch(asset['browser_download_url'], timeout=180)
    if 'sha256:' + hashlib.sha256(archive).hexdigest() != digest:
        raise Failure('Xray 下载校验失败。')
    import io
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        if s is not None:
            owned_write(s, BIN, z.read('xray'), 0o755)
        else:
            write(BIN, z.read('xray'), 0o755)
    os.chmod(BIN.parent, 0o755)


def local_setup(s, cert_token):
    remember_packages(s)
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    run('apt-get', 'update')
    s['packages_install_started'] = True
    packages_this_run_before = set(installed_packages())
    dump(STATE, s)
    try:
        run('apt-get', 'install', '-y', 'nginx', 'certbot', 'python3-certbot-dns-cloudflare',
            'curl', 'ca-certificates', 'qrencode', 'ufw', 'dnsutils')
    finally:
        s['packages_added'] = sorted(set(s.get('packages_added', [])) |
                                     (set(installed_packages()) - packages_this_run_before))
        dump(STATE, s)
    install_xray(s)
    if 'nginx_packaged' not in s:
        s['nginx_packaged'] = tree_fingerprints('/etc/nginx')
        dump(STATE, s)
    if run('id', '-u', 'xhttp-proxy', capture=True, check=False) == '':
        s['user_created'] = True
        dump(STATE, s)
        run('useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'xhttp-proxy')
    owned_write(s, ROOT / 'cloudflare.ini', 'dns_cloudflare_api_token = ' + cert_token + '\n')
    if 'certificates_before' not in s:
        s['certificates_before'] = [p.name for p in Path('/etc/letsencrypt/renewal').glob('*.conf')]
        dump(STATE, s)
    if 'certificate_existed' not in s:
        s['certificate_existed'] = Path('/etc/letsencrypt/renewal/' + s['host'] + '.conf').exists()
        dump(STATE, s)
    print('申请证书（同意 Let’s Encrypt 服务条款；DNS 验证可能需要几分钟）……')
    run('certbot', 'certonly', '--non-interactive', '--agree-tos', '--register-unsafely-without-email',
        '--dns-cloudflare', '--dns-cloudflare-credentials', ROOT / 'cloudflare.ini',
        '--dns-cloudflare-propagation-seconds', '60', '--cert-name', s['host'], '-d', s['host'],
        '--keep-until-expiring')
    owned_write(s, '/etc/letsencrypt/renewal-hooks/deploy/xhttp-cdn-nginx',
          '#!/bin/sh\n/usr/sbin/nginx -t && /usr/bin/systemctl reload nginx\n', 0o750)
    webroot = Path('/var/www/xhttp-cdn')
    webroot.mkdir(exist_ok=True)
    os.chmod(webroot, 0o755)
    owned_write(s, webroot / 'index.html', '<!doctype html><html lang="en"><meta charset="utf-8">'
          '<meta name="viewport" content="width=device-width, initial-scale=1">'
          '<title>Welcome</title><style>body{margin:15vh auto;max-width:45rem;padding:2rem;'
          'font:18px/1.7 system-ui;background:#f7f8fb;color:#283040}h1{font-size:3rem}</style>'
          '<h1>Welcome</h1><p>A quiet space for ideas and notes.</p></html>', 0o644)
    # The runtime config is outside ROOT so service user cannot read the CF credentials.
    conf = Path('/usr/local/etc/xhttp-cdn/config.json')
    old_nginx = NGINX.read_bytes() if NGINX.exists() else None
    old_xray = conf.read_bytes() if conf.exists() else None
    backup = ROOT / 'backups' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    if old_nginx:
        write(backup / 'nginx.conf', old_nginx)
    if old_xray:
        write(backup / 'xray.json', old_xray)
    owned_write(s, conf, json.dumps(server_config(s), indent=2) + '\n')
    os.chmod(conf.parent, 0o755)
    run('chown', 'root:xhttp-proxy', conf)
    os.chmod(conf, 0o640)
    owned_write(s, NGINX, nginx_config(s), 0o644)
    enabled = Path('/etc/nginx/sites-enabled/xhttp-cdn')
    if not enabled.exists():
        s.setdefault('owned_files', {})[str(enabled)] = 'symlink:' + str(NGINX)
        dump(STATE, s)
        enabled.symlink_to(NGINX)
    default = Path('/etc/nginx/sites-enabled/default')
    if default.is_symlink() and default.resolve() == Path('/etc/nginx/sites-available/default'):
        s['nginx_default_removed'] = True
        dump(STATE, s)
        default.unlink()
    owned_write(s, '/etc/systemd/system/xhttp-cdn-xray.service', f'''[Unit]
Description=XHTTP-CDN Xray
After=network-online.target
Wants=network-online.target
[Service]
User=xhttp-proxy
Group=xhttp-proxy
ExecStart={BIN} run -config {conf}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
''', 0o644)
    try:
        run(BIN, 'run', '-test', '-config', conf)
        run('nginx', '-t')
    except Exception:
        if old_nginx:
            owned_write(s, NGINX, old_nginx, 0o644)
        if old_xray:
            owned_write(s, conf, old_xray, 0o640)
            run('chown', 'root:xhttp-proxy', conf)
        raise
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'nginx', 'xhttp-cdn-xray', 'certbot.timer')
    run('systemctl', 'restart', 'xhttp-cdn-xray')
    run('systemctl', 'reload', 'nginx')
    run('systemctl', 'is-active', 'nginx', 'xhttp-cdn-xray')
    s['nginx_after'] = tree_fingerprints('/etc/nginx')
    dump(STATE, s)


def remember_ufw(s):
    if 'ufw_before' not in s:
        s['ufw_before'] = {p: base64.b64encode(Path(p).read_bytes()).decode() if Path(p).exists() else None for p in UFW_FILES}
        s['ufw_was_active'] = 'Status: active' in run('ufw', 'status', capture=True)
        s['ufw_after'] = {p: fingerprint(p) for p in UFW_FILES}
        dump(STATE, s)


def check_reused_ufw(s):
    if s.get('reuse_ufw'):
        if not s.get('ufw_guard') or ufw_guard() != s['ufw_guard']:
            raise Failure('UFW 配置在核验后发生变化，停止自动修改；保留当前规则和安装状态。')
        if 'Status: active' not in run('ufw', 'status', capture=True):
            raise Failure('原先复用的 UFW 已停用，需人工检查后继续。')
        check_firewall_backend(True)


def firewall(s, networks):
    check_reused_ufw(s)
    ports = ssh_ports()
    ufwc = Path('/etc/default/ufw').read_text()
    if not re.search(r'^IPV6=yes$', ufwc, re.M):
        raise Failure('UFW IPv6 未启用，请先启用以免漏掉 IPv6 入口。')
    remember_ufw(s)
    if s.get('reuse_ufw') and sorted(ports) != s.get('ssh_ports'):
        raise Failure('SSH 端口在核验后发生变化，停止自动修改 UFW。')
    try:
        if not s.get('reuse_ufw'):
            for p in sorted(ports):
                run('ufw', 'allow', str(p) + '/tcp', 'comment', 'XHTTP-CDN preserve SSH')
        for net in networks:
            run('ufw', 'allow', 'proto', 'tcp', 'from', net, 'to', 'any', 'port', '443',
                'comment', 'XHTTP-CDN CF')
        if not s.get('reuse_ufw'):
            run('ufw', 'default', 'deny', 'incoming')
            run('ufw', 'default', 'allow', 'outgoing')
            run('ufw', '--force', 'enable')
    finally:
        s['ufw_after'] = {p: fingerprint(p) for p in UFW_FILES}
        if s.get('reuse_ufw'):
            s['ufw_guard'] = ufw_guard()
        dump(STATE, s)
    s['cf_networks'] = networks
    s['ssh_ports'] = sorted(ports)
    dump(STATE, s)


def dns_edges(s, networks):
    # HTTPS DoH JSON, not local plaintext DNS for the private node name.
    url = 'https://dns.google/resolve?' + urllib.parse.urlencode({'name': s['host'], 'type': 'A'})
    answer = json.loads(fetch(url))
    nets = [ipaddress.ip_network(n) for n in networks]
    edges = [a['data'] for a in answer.get('Answer', []) if a['type'] == 1 and
             any(ipaddress.ip_address(a['data']) in n for n in nets)]
    if not edges:
        raise Failure('公网 DNS 尚未返回 Cloudflare A 记录；请等传播后重新执行。')
    return list(dict.fromkeys(edges))


def hello_info(data):
    """Only TLS ClientHello metadata. Does not record application traffic."""
    payload, pos = b'', 0
    while pos + 5 <= len(data):
        size = int.from_bytes(data[pos+3:pos+5], 'big')
        if pos + 5 + size > len(data):
            return None
        if data[pos] != 22:
            return None
        payload += data[pos+5:pos+5+size]
        pos += 5 + size
        if len(payload) >= 4 and len(payload) >= 4 + int.from_bytes(payload[1:4], 'big'):
            break
    if len(payload) < 4 or payload[0] != 1 or len(payload) < 4 + int.from_bytes(payload[1:4], 'big'):
        return None
    b = payload[4:4+int.from_bytes(payload[1:4], 'big')]
    p = 34
    p += 1 + b[p]
    p += 2 + int.from_bytes(b[p:p+2], 'big')
    p += 1 + b[p]
    total = int.from_bytes(b[p:p+2], 'big')
    p += 2
    end, ech, sni = p + total, False, ''
    while p + 4 <= end:
        kind, length = struct.unpack('!HH', b[p:p+4])
        value = b[p+4:p+4+length]
        if kind == 0 and len(value) >= 5:
            sni = value[5:5+int.from_bytes(value[3:5], 'big')].decode('ascii')
        if kind == 0xfe0d:
            ech = True
        p += 4 + length
    return {'outer_sni': sni, 'ech_extension': ech}


class Relay:
    def __init__(self, edge):
        self.edge, self.observations = edge, []
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(20)
        self.sock.settimeout(0.5)
        self.port, self.stop = self.sock.getsockname()[1], threading.Event()
        self.connections = []
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.sock.accept()
                threading.Thread(target=self.bridge, args=(client,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                return

    def bridge(self, client):
        try:
            server = socket.create_connection((self.edge, 443), timeout=15)
            self.connections.extend([client, server])
            client.settimeout(20)
            threading.Thread(target=self.copy, args=(server, client, False), daemon=True).start()
            self.copy(client, server, True)
        except OSError:
            client.close()

    def copy(self, src, dst, inspect):
        buf = b''
        try:
            while not self.stop.is_set():
                chunk = src.recv(65536)
                if not chunk:
                    break
                if inspect:
                    buf += chunk
                    info = hello_info(buf)
                    if info:
                        self.observations.append(info)
                        inspect, buf = False, b''
                    elif len(buf) > 131072:
                        raise OSError('ClientHello too large')
                dst.sendall(chunk)
        except (OSError, ValueError, IndexError, struct.error):
            pass
        finally:
            with contextlib.suppress(OSError):
                dst.shutdown(socket.SHUT_WR)

    def close(self):
        self.stop.set()
        self.sock.close()
        for c in self.connections:
            c.close()


def proxy_test(config):
    with tempfile.TemporaryDirectory(prefix='xhttp-test-') as td:
        p = Path(td)
        dump(p / 'client.json', config)
        with open(p / 'log', 'w') as log:
            proc = subprocess.Popen([str(BIN), 'run', '-config', str(p / 'client.json')], stdout=log, stderr=log)
            try:
                port = config['inbounds'][0]['port']
                for _ in range(30):
                    if proc.poll() is not None:
                        raise Failure('临时测试客户端退出，请检查内核配置。')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.2)
                result = run('curl', '--fail', '--silent', '--show-error', '--max-time', '40',
                    '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{port}',
                    'https://api.ipify.org', capture=True, timeout=50)
                ipaddress.ip_address(result)
                return result
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def verify(s, edges):
    # Domain address tests DNS + CF certificate + reverse proxy + VLESS auth + egress.
    result = {'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'ordinary': False, 'ech': False, 'test_location': 'VPS (not China client)',
              'xray_version': XRAY_VERSION}
    dump(OUT / 'verification.json', result)
    result['ordinary_exit'] = proxy_test(client_config(s, port=free_port()))
    result['ordinary'] = True
    dump(OUT / 'verification.json', result)
    for edge in edges:
        relay = Relay(edge)
        try:
            exit_ip = proxy_test(client_config(s, True, free_port(), '127.0.0.1', relay.port))
            seen = relay.observations
            if not seen or not all(o['ech_extension'] and o['outer_sni'] == 'cloudflare-ech.com' for o in seen):
                raise Failure('ECH 外层 ClientHello 验证失败。')
            s['edge'] = edge
            # Also test precisely the exported address, not just the instrumented relay.
            direct_exit = proxy_test(client_config(s, True, free_port()))
            if exit_ip != direct_exit or direct_exit != result['ordinary_exit']:
                raise Failure('普通/ECH 节点出口不一致，停止标记成功。')
            result.update(ech=True, ech_exit=direct_exit, edge=edge, handshake=seen[0])
            dump(OUT / 'verification.json', result)
            dump(STATE, s)
            return result
        except (Failure, OSError, ValueError) as e:
            print(f'ECH 地址 {edge} 测试失败：{e}')
        finally:
            relay.close()
    raise Failure('普通节点已通过，但 ECH 未验证通过。检查 CF ECH、DoH 可达性，稍后用 --verify 重试。未输出成功节点包。')


def export_nodes(s):
    OUT.mkdir(mode=0o700, exist_ok=True)
    os.chmod(OUT, 0o700)
    links = []
    for ech, name in ((False, 'XHTTP'), (True, 'ECH')):
        uri = node_uri(s, ech)
        write(OUT / (name + '.txt'), uri + '\n')
        dump(OUT / (name + '.json'), client_config(s, ech))
        subprocess.run(['qrencode', '-l', 'M', '-o', str(OUT / (name + '.png'))], input=uri, text=True, check=True)
        os.chmod(OUT / (name + '.png'), 0o600)
        print('\n' + name + ' 节点：\n' + uri)
        subprocess.run(['qrencode', '-t', 'ANSIUTF8', '-l', 'M'], input=uri, text=True, check=True)
        links.append(uri)
    write(OUT / 'nodes.txt', '\n'.join(links) + '\n')
    write(OUT / 'subscription.txt', base64.b64encode(('\n'.join(links) + '\n').encode()))
    for p in OUT.iterdir():
        if p.name in NODE_FILES and p.is_file():
            s.setdefault('owned_files', {})[str(p)] = fingerprint(p)
    dump(STATE, s)
    print(f'链接、PNG 二维码和配置已保存到 {OUT}（root 可读，不放在网站目录）。')


NODE_FILES = {'XHTTP.txt', 'XHTTP.json', 'XHTTP.png', 'ECH.txt', 'ECH.json', 'ECH.png',
              'nodes.txt', 'subscription.txt', 'verification.json'}


def cf_uninstall_plan(cf, s):
    """Read-only plan. Never delete a Zone, other hostnames, or a whole ruleset."""
    ops = []
    if not s.get('zone_id'):
        return ops
    base = '/zones/' + s['zone_id']
    if 'dns_before' in s:
        records = cf.api('GET', base + '/dns_records?' + urllib.parse.urlencode({'name': s['host'], 'per_page': 100}))
        current = [r for r in records if r['type'] in ('A', 'AAAA', 'CNAME')]
        old = s['dns_before']
        fields = ('type', 'name', 'content', 'ttl', 'proxied', 'comment')
        def normalized(r):
            return {k: r.get(k, '' if k == 'comment' else None) for k in fields}
        expected = dict(type='A', name=s['host'], content=s['ip'], ttl=1, proxied=True,
                        comment='Managed by XHTTP-CDN installer')
        if old and len(current) == 1 and normalized(current[0]) == normalized(old[0]):
            pass  # Already restored during an interrupted uninstall.
        elif not current and not old:
            pass
        elif len(current) == 1 and normalized(current[0]) == expected:
            path = base + '/dns_records/' + current[0]['id']
            ops.append(('PATCH', path, normalized(old[0])) if old else ('DELETE', path, None))
        else:
            raise Failure('节点 DNS 已被其他操作修改；卸载停止，避免误删。请对照 state.json 人工处理。')
    prefix = base + '/rulesets'
    ruleset = None
    if s.get('cache_started'):
        try:
            ruleset = cf.api('GET', prefix + '/phases/http_request_cache_settings/entrypoint')
        except APIError as e:
            if e.status != 404:
                raise
    if ruleset:
        ref = 'xhttp-cdn_' + hashlib.sha256(s['host'].encode()).hexdigest()[:16]
        r = next((r for r in ruleset.get('rules', []) if r.get('ref') == ref), None)
        if r:
            expected = {'action': 'set_cache_settings', 'action_parameters': {'cache': False},
                        'expression': f'(http.host eq "{s["host"]}")', 'enabled': True}
            old_rule = next((x for x in s.get('cache_before', {}).get('rules', []) if x.get('ref') == ref), None)
            if old_rule and all(r.get(k) == old_rule.get(k) for k in expected):
                pass
            elif not all(r.get(k) == v for k, v in expected.items()):
                raise Failure('节点缓存规则已被修改，卸载停止以保留改动。')
            else:
                path = prefix + '/' + ruleset['id'] + '/rules/' + r['id']
                if old_rule:
                    body = {k: old_rule[k] for k in ('ref', 'description', 'expression', 'action', 'action_parameters', 'enabled') if k in old_rule}
                    ops.append(('PATCH', path, body))
                else:
                    ops.append(('DELETE', path, None))
    desired = {'ssl': 'strict', 'tls_1_3': 'on', 'http2': 'on', 'ech': 'on'}
    for setting, before in s.get('settings_before', {}).items():
        if setting not in desired:
            raise Failure('状态中含未知 CF 设置，停止卸载。')
        current = cf.api('GET', base + '/settings/' + setting)['value']
        if current == before:
            continue
        if current != desired[setting]:
            raise Failure(f'CF {setting} 后来被修改；卸载停止，避免覆盖。')
        ops.append(('PATCH', base + '/settings/' + setting, {'value': before}))
    return ops


def owned_path_allowed(path):
    p = Path(path)
    # Exact allowlist; never delete arbitrary paths supplied by a state file.
    fixed = {BIN, NGINX, ROOT / 'cloudflare.ini', Path('/usr/local/etc/xhttp-cdn/config.json'),
             Path('/etc/nginx/sites-enabled/xhttp-cdn'),
             Path('/etc/systemd/system/xhttp-cdn-xray.service'),
             Path('/etc/letsencrypt/renewal-hooks/deploy/xhttp-cdn-nginx'),
             Path('/var/www/xhttp-cdn/index.html')}
    return p in fixed or (p.parent == OUT and p.name in NODE_FILES)


def local_uninstall_check(s):
    if s.get('reuse_ufw') and not s.get('ufw_restored'):
        check_reused_ufw(s)
    if s.get('schema', 1) < 2:
        raise Failure('旧版安装没有完整归属清单，无法安全自动清理。请人工审查；不能靠升级推断历史软件归属。')
    if 'certificates_before' in s:
        now = {p.name for p in Path('/etc/letsencrypt/renewal').glob('*.conf')}
        if now - set(s['certificates_before']) - {s['host'] + '.conf'}:
            raise Failure('Certbot 后来新增了其他证书，卸载停止以保护其他用途。')
    for name, digest in s.get('owned_files', {}).items():
        if not owned_path_allowed(name):
            raise Failure('卸载清单包含非本程序路径，停止。')
        actual = fingerprint(name)
        # Verification report is intentionally updated by --verify, including failure reports.
        if Path(name) != OUT / 'verification.json' and actual is not None and actual != digest:
            raise Failure(f'本地文件后来被修改，卸载停止：{name}')
    if s.get('ufw_before') and not s.get('ufw_restored'):
        if not s.get('ufw_after'):
            raise Failure('防火墙步骤曾异常中断且没有完成快照，需人工检查。')
        for name, digest in s['ufw_after'].items():
            if fingerprint(name) != digest:
                raise Failure('UFW 已有后续改动，卸载停止以保留规则：' + name)
    # Detect newly added sites/config edits before removing nginx packages or service.
    if s.get('nginx_packaged') and not s.get('local_removed'):
        expected = dict(s['nginx_packaged'])
        expected.update({k: v for k, v in s.get('owned_files', {}).items() if k.startswith('/etc/nginx/')})
        if s.get('nginx_default_removed'):
            expected.pop('/etc/nginx/sites-enabled/default', None)
        current = tree_fingerprints('/etc/nginx')
        # Missing managed files are fine when resuming partial cleanup. Unknown/changed files are not.
        for name, digest in current.items():
            if expected.get(name) != digest:
                raise Failure('检测到 Nginx 其他用途或后续改动，停止卸载：' + name)


def package_removal_plan(s):
    before = set(s.get('packages_before', []))
    current = set(installed_packages())
    candidates = sorted((set(s.get('packages_added', [])) & current) - before)
    if not candidates:
        return []
    protected = re.compile(r'^(?:linux-|(?:openssh|systemd|libc6|sudo|bash|apt|dpkg)(?:[-:]|$))')
    if any(protected.match(p) for p in candidates):
        raise Failure('新增软件包含系统关键组件，请人工审查卸载清单。')
    simulated = run('apt-get', '-s', 'purge', *candidates, capture=True)
    removed = set(re.findall(r'^(?:Remv|Purg) (\S+)', simulated, re.M))
    # Apt may omit architecture suffixes; compare both forms conservatively.
    allowed = set(candidates) | {x.split(':')[0] for x in candidates}
    original = before | {x.split(':')[0] for x in before}
    if not removed or removed - allowed or removed & original or any(protected.match(p) for p in removed):
        raise Failure('APT 预计影响已有/后来安装的软件，停止卸载；可使用 --keep-packages 保留软件仅清理节点。')
    return candidates


def uninstall(s, keep_packages=False):
    if not s:
        print('未找到本安装器状态，无内容可卸载。')
        return
    local_uninstall_check(s)
    packages = [] if keep_packages else package_removal_plan(s)
    print('卸载对象：' + s['host'])
    print('CF：删除节点记录或恢复原记录、清理本节点缓存规则、恢复安装前的区域设置。')
    print('VPS：停止代理和本次 Nginx、删除本程序配置/证书/节点文件、恢复原防火墙。')
    print('将卸载新增软件：' + (', '.join(packages) or '无（已有软件或选择保留）'))
    print('保留整个 CF Zone、其他 DNS、注册商 NS、共享 ACME 账户及系统历史日志。')
    cf = None
    ops = []
    if not s.get('cf_removed') and s.get('zone_id'):
        cf = CF(token_input('用于 CF 清理的 API Token（隐藏输入，需要原安装权限）：'))
        ops = cf_uninstall_plan(cf, s)
        print('CF 待恢复/删除操作数：' + str(len(ops)))
    if not confirm_input('确认立即中断该节点并卸载，输入 UNINSTALL（不区分大小写）：', 'UNINSTALL'):
        raise Failure('未执行卸载。')
    s['uninstall_started'] = True
    dump(STATE, s)
    if cf:
        # Refresh plan after interactive confirmation, in case resources changed while waiting.
        for method, path, body in cf_uninstall_plan(cf, s):
            cf.api(method, path, body)
        s['cf_removed'] = True
        dump(STATE, s)
    # API failure above leaves local service intact, so retry can finish cloud cleanup first.
    if not s.get('local_removed'):
        run('systemctl', 'disable', '--now', 'xhttp-cdn-xray.service', check=False)
        if s.get('nginx_packaged'):
            run('systemctl', 'disable', '--now', 'nginx', check=False)
        timer = s.get('certbot_timer_before', {})
        if not timer.get('enabled'):
            run('systemctl', 'disable', 'certbot.timer', check=False)
        if not timer.get('active'):
            run('systemctl', 'stop', 'certbot.timer', check=False)
        if s.get('certificate_existed') is False and Path('/etc/letsencrypt/renewal/' + s['host'] + '.conf').exists():
            run('certbot', 'delete', '--non-interactive', '--cert-name', s['host'])
        if s.get('ufw_before') and not s.get('ufw_restored'):
            if not s.get('reuse_ufw'):
                run('ufw', '--force', 'disable')
            for name, content in s['ufw_before'].items():
                if name not in UFW_FILES:
                    raise Failure('未知 UFW 路径，停止恢复。')
                if content is None:
                    Path(name).unlink(missing_ok=True)
                else:
                    write(name, base64.b64decode(content), 0o640)
            if s.get('reuse_ufw'):
                run('ufw', 'reload')
            elif s.get('ufw_was_active'):
                run('ufw', '--force', 'enable')
            s['ufw_restored'] = True
            dump(STATE, s)
        for name in s.get('owned_files', {}):
            Path(name).unlink(missing_ok=True)
        # The report may exist after a failed initial verify, before export recorded it.
        (OUT / 'verification.json').unlink(missing_ok=True)
        run('systemctl', 'daemon-reload')
        if s.get('user_created') and run('id', '-u', 'xhttp-proxy', capture=True, check=False):
            run('userdel', 'xhttp-proxy')  # No recursive home deletion.
        s['local_removed'] = True
        dump(STATE, s)
    if packages:
        # Recompute just before purge to detect new dependencies introduced during cleanup.
        packages = package_removal_plan(s)
        if packages:
            run('apt-get', '-y', 'purge', *packages)
    if keep_packages:
        print('已按要求保留系统软件包。')
    # Empty directory removal only; preserve unexpected files instead of recursive deletion.
    for directory in (OUT, BIN.parent, Path('/usr/local/etc/xhttp-cdn'), Path('/var/www/xhttp-cdn')):
        with contextlib.suppress(OSError):
            directory.rmdir()
    for p in (ROOT / 'backups').glob('*/*'):
        if p.name in ('nginx.conf', 'xray.json') and p.is_file() and not p.is_symlink():
            p.unlink()
    for p in (ROOT / 'backups').glob('*'):
        with contextlib.suppress(OSError):
            p.rmdir()
    with contextlib.suppress(OSError):
        (ROOT / 'backups').rmdir()
    STATE.unlink()
    with contextlib.suppress(OSError):
        ROOT.rmdir()
    print('本次部署的 CF 节点配置和 VPS 节点已卸载。整个域名区域和注册商 NS 保留。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--verify', action='store_true', help='重新测试并导出；无需安装 Token')
    group.add_argument('--export', action='store_true', help='仅重新导出；不代表当前可连接')
    group.add_argument('--status', action='store_true', help='查看服务和最后验证结果')
    group.add_argument('--uninstall', action='store_true', help='恢复 CF 设置、移除本次 VPS 配置和新增软件')
    parser.add_argument('--keep-packages', action='store_true', help='配合 --uninstall，仅清配置，保留 apt 软件包')
    parser.add_argument('--reuse-ufw', action='store_true', help='兼容旧命令：要求复用已启用的基础 SSH UFW；默认安装已自动检测，无需此参数')
    parser.add_argument('--doh', default=None, help='ECH 配置查询 DoH URL，默认 https://dns.alidns.com/dns-query')
    args = parser.parse_args()
    if args.keep_packages and not args.uninstall:
        raise Failure('--keep-packages 只能与 --uninstall 一起使用。')
    if args.reuse_ufw and any((args.uninstall, args.verify, args.export, args.status)):
        raise Failure('--reuse-ufw 只用于安装；后续重复安装会自动沿用该选择。')
    if sys.version_info < (3, 10):
        raise Failure('需要 Python 3.10 或更高版本。')
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise Failure('请在 Linux VPS 上以 root 运行。')
    import fcntl
    lock = open('/run/lock/xhttp-cdn.lock', 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Failure('另一个安装进程正在运行。') from None
    os.umask(0o077)
    os.environ['LC_ALL'] = 'C.UTF-8'
    s = json.loads(STATE.read_text()) if STATE.exists() else None
    if args.uninstall:
        uninstall(s, args.keep_packages)
        return
    if s and s.get('uninstall_started') and not args.status:
        raise Failure('上次卸载未完成，请使用 --uninstall 继续，不要重新安装覆盖恢复记录。')
    if args.status:
        run('systemctl', '--no-pager', 'status', 'nginx', 'xhttp-cdn-xray', 'certbot.timer', check=False)
        if (OUT / 'verification.json').exists():
            print((OUT / 'verification.json').read_text())
        return
    if args.verify or args.export:
        if not s or 'edge' not in s:
            raise Failure('还没有完成服务器配置，请先执行安装。')
        if args.doh:
            s['doh'] = validate_doh(args.doh)
        if args.verify:
            verify(s, dns_edges(s, get_networks()))
        else:
            print('注意：仅导出保存的配置，本次没有验证连通性。')
        export_nodes(s)
        return
    if s and args.reuse_ufw and not s.get('reuse_ufw'):
        raise Failure('不能用 --reuse-ufw 改变已有安装的防火墙管理方式。')
    guard = preflight(s is not None, args.reuse_ufw)
    if s:
        check_reused_ufw(s)
    if not s:
        host = domain(input('节点完整域名（例如 node.example.com）：'))
        zone = domain(input('根域名 / CF Zone（例如 example.com）：'))
        if not host.endswith('.' + zone):
            raise Failure('请使用该根域名下的子域名作为节点。')
        detected = fetch('https://api4.ipify.org').decode().strip()
        ip = input(f'服务器公网 IPv4 [{detected}]：').strip() or detected
        if not isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address) or not ipaddress.ip_address(ip).is_global:
            raise Failure('需要公网 IPv4。')
        s = {'schema': 2, 'host': host, 'zone': zone, 'ip': ip,
             'uuid': str(uuid.uuid4()), 'path': '/' + secrets.token_hex(20) + '/',
             'doh': 'https://dns.alidns.com/dns-query', 'installer_version': VERSION}
        if guard is not None:
            s.update(reuse_ufw=True, ufw_guard=guard, ssh_ports=sorted(ssh_ports()))
    if args.doh:
        s['doh'] = validate_doh(args.doh)
    print(f'目标：{s["host"]} → {s["ip"]}；传输模式 packet-up。')
    print('将修改该 CF 区域的 SSL/TLS 与 HTTP/2 设置，并创建节点记录和缓存绕过规则。')
    print('将安装服务、启用主机防火墙并保留 SSH；申请证书即同意 Let’s Encrypt 服务条款。')
    if s.get('reuse_ufw'):
        print('本次复用已有基础 UFW：保留现有 SSH 规则和默认策略，只追加 CF 的 443 回源放行。')
    if not confirm_input('确认用于新/本脚本管理的 VPS，输入 YES 继续（不区分大小写）：', 'YES'):
        raise Failure('未执行安装。')
    token = token_input('Cloudflare 安装 API Token（隐藏输入）：')
    print('证书续期需要持久保存 Token，文件仅 root 可读。可另用仅此域名 DNS 编辑权限的 Token。')
    extra = getpass.getpass('续期专用 DNS Token（留空则保存同一个安装 Token）：').strip()
    if extra and not re.fullmatch(r'[A-Za-z0-9_-]{20,256}', extra):
        raise Failure('续期 Token 格式不正确。')
    check_reused_ufw(s)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    os.chmod(ROOT, 0o700)
    dump(STATE, s)
    if s.get('reuse_ufw'):
        remember_ufw(s)
    remember_packages(s)
    cf = CF(token)
    zone_setup(cf, s)
    cloudflare_setup(cf, s)
    networks = get_networks()
    local_setup(s, extra or token)
    firewall(s, networks)
    print('等待 CF DNS/边缘证书生效，然后执行端到端测试……')
    for attempt in range(20):
        try:
            edges = dns_edges(s, networks)
            s['edge'] = edges[0]
            dump(STATE, s)
            fetch('https://' + s['host'] + '/', timeout=20)
            break
        except (Failure, OSError, ValueError):
            if attempt == 19:
                raise Failure('CF DNS/HTTPS 尚不可用；检查边缘证书、CAA、回源和云防火墙，稍后重新执行。')
            print('尚未就绪，15 秒后重试……', flush=True)
            time.sleep(15)
    verify(s, edges)
    export_nodes(s)
    print('安装及 VPS 侧普通/ECH 测试通过。请在你的实际网络导入客户端验证。')


def validate_doh(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or '\n' in url:
        raise Failure('DoH 必须是无内嵌凭据的 HTTPS URL。')
    return url


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n已中断。保留已完成步骤，重新执行可继续。', file=sys.stderr)
        sys.exit(130)
    except (Failure, OSError, ValueError, subprocess.SubprocessError, StopIteration, KeyError) as e:
        print('\n失败：' + str(e), file=sys.stderr)
        if STATE.exists():
            print('未宣称安装成功。状态保存在 /etc/xhttp-cdn；不要删除后盲目重装。', file=sys.stderr)
        else:
            print('安装在写入状态前停止，尚未创建安装状态；无需删除 /etc/xhttp-cdn。', file=sys.stderr)
        sys.exit(1)
