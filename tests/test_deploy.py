import copy
from contextlib import contextmanager
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs, unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deploy as d


def sample():
    return {'host': 'node.example.com', 'zone': 'example.com', 'zone_id': 'zone1',
            'uuid': 'e051aa14-0404-4445-9710-15422b24ae2e', 'path': '/0123456789abcdef/',
            'ip': '192.0.2.10', 'edge': '203.0.113.2', 'doh': 'https://dns.alidns.com/dns-query'}


class FakeCF:
    def __init__(self, rules=None, error=None):
        self.rules, self.error, self.calls = rules, error, []

    def api(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == 'GET':
            if self.error:
                raise d.APIError(self.error, 'test failure')
            return {'id': 'rs1', 'rules': self.rules}
        return {}


def hello(sni='cloudflare-ech.com', ech=True):
    name = sni.encode()
    entry = b'\0' + struct.pack('!H', len(name)) + name
    s = struct.pack('!H', len(entry)) + entry
    ext = struct.pack('!HH', 0, len(s)) + s
    if ech:
        ext += struct.pack('!HH', 0xfe0d, 3) + b'abc'
    body = b'\x03\x03' + b'x' * 32 + b'\0' + b'\0\2\x13\1' + b'\1\0' + struct.pack('!H', len(ext)) + ext
    hand = b'\1' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\1' + len(hand).to_bytes(2, 'big') + hand


class Tests(unittest.TestCase):
    def test_domain_injection_rejected(self):
        for bad in ['example.com;id', 'https://example.com', 'x/a.com', 'x\n.com', 'a..com', '-a.com']:
            with self.subTest(bad=bad), self.assertRaises(d.Failure):
                d.domain(bad)
        self.assertEqual(d.domain('Node.Example.COM.'), 'node.example.com')

    def test_doh_rejects_cleartext_and_embedded_password(self):
        for bad in ['http://dns.google/dns-query', 'https://user:pass@dns.google/dns-query']:
            with self.assertRaises(d.Failure):
                d.validate_doh(bad)

    def test_links_have_expected_security_properties(self):
        s = sample()
        for ech in [False, True]:
            link = urlsplit(d.node_uri(s, ech))
            q = parse_qs(link.query)
            self.assertEqual(link.hostname, s['edge'] if ech else s['host'])
            self.assertEqual(q['path'], [s['path']])
            self.assertEqual(q['mode'], ['packet-up'])
            self.assertEqual(q['security'], ['tls'])
            self.assertEqual('ech' in q, ech)
            if ech:
                self.assertEqual(q['ech'], [s['doh']])
            self.assertNotIn('allowInsecure', q)

    def test_no_token_in_configs(self):
        s = sample()
        s['token'] = 'secret-do-not-export'
        self.assertNotIn(s['token'], json.dumps(d.client_config(s, True)))
        self.assertNotIn(s['token'], json.dumps(d.server_config(s)))
        self.assertNotIn(s['token'], d.node_uri(s, True))

    def test_api_error_redacts_token(self):
        import urllib.error
        from io import BytesIO
        cf = d.CF('token-must-not-be-repeated')
        err = urllib.error.HTTPError('https://api.cloudflare.com', 403, 'denied', {},
                                    BytesIO(b'token-must-not-be-repeated'))
        with patch.object(d.HTTP, 'open', side_effect=err):
            with self.assertRaises(d.APIError) as c:
                cf.api('GET', '/zones')
        self.assertNotIn(cf.token, str(c.exception))

    def test_existing_cache_rules_not_replaced(self):
        cf = FakeCF([{'id': 'other', 'ref': 'other-rule'}])
        with patch.object(d, 'dump'):
            d.cache_rule(cf, 'z', 'node.example.com', {})
        mutations = [x for x in cf.calls if x[0] != 'GET']
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0][0], 'POST')
        self.assertTrue(mutations[0][1].endswith('/rs1/rules'))
        self.assertEqual(mutations[0][2]['action_parameters'], {'cache': False})
        self.assertEqual(mutations[0][2]['position'], {'after': ''})

    def test_cache_resume_updates_owned_rule(self):
        host = 'node.example.com'
        ref = 'xhttp-cdn_' + hashlib.sha256(host.encode()).hexdigest()[:16]
        cf = FakeCF([{'id': 'own', 'ref': ref}, {'id': 'other'}])
        with patch.object(d, 'dump'):
            d.cache_rule(cf, 'z', host, {})
        self.assertEqual(cf.calls[-1][0], 'PATCH')
        self.assertTrue(cf.calls[-1][1].endswith('/rules/own'))

    def test_cache_404_creates_but_403_does_not(self):
        cf = FakeCF(error=404)
        with patch.object(d, 'dump'):
            d.cache_rule(cf, 'z', 'node.example.com', {})
        self.assertEqual(cf.calls[-1][0], 'POST')
        cf = FakeCF(error=403)
        with self.assertRaises(d.APIError):
            d.cache_rule(cf, 'z', 'node.example.com', {})
        self.assertEqual(len(cf.calls), 1)

    def test_hello_parser_distinguishes_clear_sni(self):
        self.assertEqual(d.hello_info(hello()), {'outer_sni': 'cloudflare-ech.com', 'ech_extension': True})
        self.assertEqual(d.hello_info(hello('node.example.com', False)),
                         {'outer_sni': 'node.example.com', 'ech_extension': False})
        self.assertIsNone(d.hello_info(hello()[:30]))

    def test_fragmented_tls_records(self):
        raw = hello()[5:]
        first, second = raw[:20], raw[20:]
        split = b'\x16\x03\x03' + len(first).to_bytes(2, 'big') + first + \
                b'\x16\x03\x03' + len(second).to_bytes(2, 'big') + second
        self.assertEqual(d.hello_info(split)['outer_sni'], 'cloudflare-ech.com')

    def test_ech_failure_never_marked_success(self):
        s = sample()
        writes = []
        with patch.object(d, 'proxy_test', side_effect=['192.0.2.10', d.Failure('handshake failed')]), \
             patch.object(d, 'Relay') as relay, \
             patch.object(d, 'dump', side_effect=lambda p, v: writes.append(copy.deepcopy(v))):
            relay.return_value.port = 23456
            with self.assertRaises(d.Failure):
                d.verify(s, [s['edge']])
        self.assertTrue(writes[-1]['ordinary'])
        self.assertFalse(writes[-1]['ech'])

    def test_exported_ech_address_is_retested(self):
        s = sample()
        with patch.object(d, 'proxy_test', return_value='192.0.2.10') as test, \
             patch.object(d, 'Relay') as relay, patch.object(d, 'dump'):
            relay.return_value.port = 23456
            relay.return_value.observations = [{'outer_sni': 'cloudflare-ech.com', 'ech_extension': True}]
            result = d.verify(s, [s['edge']])
        self.assertTrue(result['ech'])
        self.assertEqual(test.call_count, 3)
        self.assertEqual(test.call_args_list[-1].args[0]['outbounds'][0]['settings']['vnext'][0]['address'], s['edge'])

    def test_server_blocks_private_destinations(self):
        c = d.server_config(sample())
        self.assertEqual(c['inbounds'][0]['listen'], '127.0.0.1')
        self.assertIn('169.254.0.0/16', c['routing']['rules'][0]['ip'])
        self.assertEqual(c['routing']['domainStrategy'], 'IPOnDemand')

    def test_atomic_write_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'file'
            d.write(p, 'original')
            d.write(p, 'updated')
            self.assertEqual(p.read_text(), 'updated')
            try:
                (Path(td) / 'link').symlink_to(p)
            except OSError:
                self.skipTest('Symlink creation unavailable')
            with self.assertRaises(d.Failure):
                d.write(Path(td) / 'link', 'bad')


class FirewallTests(unittest.TestCase):
    status = ('Status: active\nLogging: on (low)\n'
              'Default: deny (incoming), allow (outgoing), disabled (routed)\n'
              'New profiles: skip\n\nTo                         Action      From\n'
              '--                         ------      ----\n'
              '22/tcp                     ALLOW IN    Anywhere\n'
              '22/tcp (v6)                ALLOW IN    Anywhere (v6)\n')
    backend = ('*filter\n:INPUT DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n'
               ':ufw-before-input - [0:0]\n:ufw-user-input - [0:0]\n'
               '-A INPUT -j ufw-before-input\n'
               '-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n')

    def audit(self, status=None, added='Added user rules:\nufw allow 22/tcp'):
        with patch.object(d, 'run', side_effect=[status or self.status, added]), \
             patch.object(d, 'ssh_ports', return_value={22}), \
             patch.object(d.Path, 'read_text', return_value='IPV6=yes\n'), \
             patch.object(d, 'ufw_guard', return_value={'file': 'original'}):
            return d.audit_basic_ufw()

    def test_basic_dual_stack_ssh_is_accepted(self):
        self.assertEqual(self.audit(), {'file': 'original'})

    @contextmanager
    def preflight_env(self, active=True, installed=True):
        with patch.object(d.platform, 'system', return_value='Linux'), \
             patch.object(d.os, 'geteuid', return_value=0, create=True), \
             patch.object(d.Path, 'read_text', return_value='ID=ubuntu\nVERSION_ID="26.10"'), \
             patch.object(d.Path, 'exists', autospec=True, side_effect=lambda p: str(p).replace('\\', '/') == '/run/systemd/system'), \
             patch.object(d.shutil, 'which', return_value='present' if installed else None), \
             patch.object(d, 'run', side_effect=lambda *a, **kw: '' if a[0] == 'ss' else
                          ('Status: active' if active else 'Status: inactive')), \
             patch.object(d, 'audit_basic_ufw', return_value={'file': 'original'}) as audit, \
             patch.object(d, 'check_firewall_backend') as backend:
            yield audit, backend

    def test_default_preflight_selects_active_inactive_or_missing_ufw(self):
        for installed, active in ((True, True), (True, False), (False, False)):
            with self.subTest(installed=installed, active=active), self.preflight_env(active, installed) as (audit, backend):
                result = d.preflight(False)
                self.assertEqual(result, {'file': 'original'} if active else None)
                self.assertEqual(audit.call_count, int(active))
                backend.assert_called_once_with(active)

    def test_legacy_reuse_flag_still_requires_active_ufw(self):
        with self.preflight_env() as (audit, backend):
            self.assertEqual(d.preflight(False, True), {'file': 'original'})
            audit.assert_called_once()
        with self.preflight_env(active=False) as (audit, backend):
            with self.assertRaisesRegex(d.Failure, '--reuse-ufw'):
                d.preflight(False, True)
            audit.assert_not_called()
            backend.assert_not_called()

    def test_auto_detection_never_falls_back_after_failed_audit(self):
        with self.preflight_env() as (audit, backend):
            audit.side_effect = d.Failure('extra rules')
            with self.assertRaisesRegex(d.Failure, 'extra rules'):
                d.preflight(False)
            backend.assert_not_called()
        with self.preflight_env() as (audit, backend):
            backend.side_effect = d.Failure('foreign firewall')
            with self.assertRaisesRegex(d.Failure, 'foreign firewall'):
                d.preflight(False)

    def test_resume_does_not_reclassify_existing_installation(self):
        with self.preflight_env() as (audit, backend):
            self.assertIsNone(d.preflight(True))
            audit.assert_not_called()
            backend.assert_not_called()

    def test_broad_port_or_mismatched_live_rules_rejected(self):
        for added in ('ufw allow 22/tcp\nufw allow 443/tcp', 'ufw allow OpenSSH', 'ufw allow 2222/tcp', ''):
            with self.subTest(added=added), self.assertRaises(d.Failure):
                self.audit(added=added)
        for status in (self.status.replace('deny (incoming)', 'allow (incoming)'),
                       self.status.replace('22/tcp (v6)', '443/tcp (v6)'),
                       self.status.replace('22/tcp (v6)                ALLOW IN    Anywhere (v6)\n', ''),
                       self.status + '443/tcp ALLOW IN Anywhere\n'):
            with self.subTest(status=status), self.assertRaises(d.Failure):
                self.audit(status=status)

    def test_ufw_backend_is_allowed_but_other_managers_rejected(self):
        with patch.object(d.shutil, 'which', return_value='present'), \
             patch.object(d, 'run', side_effect=[self.backend, self.backend.replace('ufw-', 'ufw6-'), 'table ip filter\ntable ip6 filter']):
            d.check_firewall_backend(True)
        for raw in (self.backend + '*nat\nCOMMIT', self.backend + ':DOCKER - [0:0]',
                    self.backend + '-A INPUT -p tcp --dport 443 -j ACCEPT'):
            with self.subTest(raw=raw), patch.object(d.shutil, 'which', return_value='present'), \
                 patch.object(d, 'run', return_value=raw), self.assertRaises(d.Failure):
                d.check_firewall_backend(True)
        with patch.object(d.shutil, 'which', return_value='present'), \
             patch.object(d, 'run', side_effect=[self.backend, self.backend, 'table inet other']), \
             self.assertRaises(d.Failure):
            d.check_firewall_backend(True)
        with patch.object(d.shutil, 'which', return_value='present'), \
             patch.object(d, 'run', return_value=self.backend), self.assertRaises(d.Failure):
            d.check_firewall_backend(False)

    def test_changed_baseline_stops_before_any_mutation(self):
        with patch.object(d, 'ufw_guard', return_value={'file': 'changed'}), patch.object(d, 'run') as run:
            with self.assertRaises(d.Failure):
                d.firewall({'reuse_ufw': True, 'ufw_guard': {'file': 'original'}}, ['192.0.2.0/24'])
            run.assert_not_called()

    def test_reuse_only_adds_cf_rules_and_keeps_initial_backup_on_retry(self):
        s = {'reuse_ufw': True, 'ufw_guard': {'file': 'original'}, 'ssh_ports': [22],
             'ufw_before': {'file': 'original bytes'}, 'ufw_was_active': True}
        def command(*args, **kwargs):
            return 'Status: active' if args[:2] == ('ufw', 'status') else ''
        with patch.object(d, 'ufw_guard', return_value={'file': 'original'}), \
             patch.object(d, 'check_firewall_backend'), patch.object(d, 'ssh_ports', return_value={22}), \
             patch.object(d.Path, 'read_text', return_value='IPV6=yes\n'), \
             patch.object(d, 'fingerprint', return_value='hash'), patch.object(d, 'dump'), \
             patch.object(d, 'run', side_effect=command) as run:
            for _ in range(2):
                d.firewall(s, ['192.0.2.0/24', '2001:db8::/32'])
        changes = [call.args for call in run.call_args_list if call.args[:2] != ('ufw', 'status')]
        self.assertEqual(len(changes), 4)
        self.assertTrue(all(cmd[:4] == ('ufw', 'allow', 'proto', 'tcp') and '443' in cmd for cmd in changes))
        self.assertEqual(s['ufw_before'], {'file': 'original bytes'})
        self.assertTrue(s['ufw_was_active'])

    def test_application_profile_does_not_change_active_config_guard(self):
        with patch.object(d, 'tree_fingerprints', return_value={
                '/etc/ufw/user.rules': 'rules', '/etc/ufw/applications.d/nginx': 'profile'}), \
             patch.object(d, 'fingerprint', return_value='defaults'):
            self.assertEqual(d.ufw_guard(), {'/etc/ufw/user.rules': 'rules', '/etc/default/ufw': 'defaults'})


@unittest.skipUnless(os.environ.get('XRAY_TEST_BINARY'), 'Set XRAY_TEST_BINARY for real core integration')
class CoreTests(unittest.TestCase):
    def test_real_core_validates_all_configs(self):
        with tempfile.TemporaryDirectory() as td:
            for name, config in [('server', d.server_config(sample())),
                                 ('plain', d.client_config(sample())), ('ech', d.client_config(sample(), True))]:
                p = Path(td) / (name + '.json')
                d.dump(p, config)
                r = subprocess.run([os.environ['XRAY_TEST_BINARY'], 'run', '-test', '-config', str(p)],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_packet_up_actual_transfer_auth_and_private_block(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'xhttp-cdn-integration-ok')

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for block, correct_uuid in [(False, True), (False, False), (True, True)]:
                with self.subTest(block=block, correct_uuid=correct_uuid), tempfile.TemporaryDirectory() as td:
                    s = sample()
                    backend, socks = d.free_port(), d.free_port()
                    sc = d.server_config(s)
                    sc['inbounds'][0]['port'] = backend
                    # New Xray also blocks private addresses in freedom by default;
                    # override only for the local test endpoint, never in production.
                    sc['outbounds'][0]['settings'] = {'finalRules': [
                        {'action': 'allow', 'ip': ['127.0.0.1/32']}]}
                    if not block:
                        sc.pop('routing')  # Test-only allowance for loopback echo endpoint.
                    cc = d.client_config(s, port=socks, address='127.0.0.1', remote_port=backend)
                    transport = cc['outbounds'][0]['streamSettings']
                    transport['security'] = 'none'
                    transport.pop('tlsSettings')
                    if not correct_uuid:
                        cc['outbounds'][0]['settings']['vnext'][0]['users'][0]['id'] = 'f051aa14-0404-4445-9710-15422b24ae2e'
                    processes = []
                    logs = []
                    try:
                        for name, config in [('server', sc), ('client', cc)]:
                            config['log']['loglevel'] = 'debug'
                            p = Path(td) / (name + '.json')
                            d.dump(p, config)
                            logs.append(open(Path(td) / (name + '.log'), 'w'))
                            processes.append(subprocess.Popen([os.environ['XRAY_TEST_BINARY'], 'run', '-config', str(p)],
                                             stdout=logs[-1], stderr=logs[-1]))
                        time.sleep(0.7)
                        r = subprocess.run(['curl', '--silent', '--fail', '--max-time', '5', '--noproxy', '',
                                            '--proxy', f'socks5h://127.0.0.1:{socks}',
                                            f'http://127.0.0.1:{server.server_port}/'], capture_output=True)
                        if correct_uuid and not block:
                            diagnostic = '\n'.join((Path(td) / (n + '.log')).read_text(errors='replace') for n in ['server', 'client'])
                            self.assertEqual(r.returncode, 0, diagnostic)
                            self.assertEqual(r.stdout, b'xhttp-cdn-integration-ok')
                        else:
                            self.assertNotEqual(r.returncode, 0)
                    finally:
                        for p in processes:
                            p.terminate()
                            p.wait(timeout=5)
                        for log in logs:
                            log.close()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
