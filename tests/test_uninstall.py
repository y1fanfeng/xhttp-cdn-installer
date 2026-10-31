import base64
import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deploy as d


def state():
    return {'schema': 2, 'host': 'node.example.com', 'zone': 'example.com', 'zone_id': 'zone',
            'ip': '192.0.2.10', 'dns_before': [], 'settings_before': {'ssl': 'full'},
            'owned_files': {}, 'packages_before': ['base', 'curl'], 'cache_started': True}


class Cloud:
    def __init__(self):
        self.calls = []
        self.records = [{'id': 'main', 'type': 'A', 'name': 'example.com', 'content': '192.0.2.30', 'ttl': 1, 'proxied': True}]
        self.settings = {'ssl': 'strict', 'tls_1_3': 'on', 'http2': 'on', 'ech': 'on'}
        self.rules = [{'id': 'other', 'ref': 'business', 'expression': '(http.host eq "www.example.com")'}]

    def node(self):
        self.records.append({'id': 'vpn', 'type': 'A', 'name': 'node.example.com', 'content': '192.0.2.10',
                             'ttl': 1, 'proxied': True, 'comment': 'Managed by XHTTP-CDN installer'})
        self.rules.append({'id': 'vpnrule', 'ref': 'xhttp-cdn_' + hashlib.sha256(b'node.example.com').hexdigest()[:16],
                           'expression': '(http.host eq "node.example.com")', 'action': 'set_cache_settings',
                           'action_parameters': {'cache': False}, 'enabled': True})

    def api(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == 'GET':
            if path.startswith('/zones?'):
                return [{'id': 'zone', 'status': 'active', 'name_servers': ['a.ns.cloudflare.com']}]
            if '/dns_records?' in path:
                return [copy.deepcopy(r) for r in self.records if r['name'] == 'node.example.com']
            if '/settings/' in path:
                return {'value': self.settings[path.rsplit('/', 1)[-1]], 'editable': True}
            if '/rulesets/' in path:
                return {'id': 'ruleset', 'rules': copy.deepcopy(self.rules)}
        if '/dns_records' in path:
            if method == 'POST':
                self.records.append({'id': 'vpn', **body})
            elif method == 'PATCH':
                self.records = [({'id': r['id'], **body} if r['id'] == path.rsplit('/', 1)[-1] else r) for r in self.records]
            elif method == 'DELETE':
                self.records = [r for r in self.records if r['id'] != path.rsplit('/', 1)[-1]]
        elif '/settings/' in path:
            self.settings[path.rsplit('/', 1)[-1]] = body['value']
        elif '/rulesets/' in path and method == 'DELETE':
            self.rules = [r for r in self.rules if r['id'] != path.rsplit('/', 1)[-1]]
        return {}


class UninstallTests(unittest.TestCase):
    def test_existing_zone_without_node_is_supported(self):
        cloud, s = Cloud(), state()
        original = copy.deepcopy(cloud.records[0])
        with patch.object(d, 'dump'):
            d.zone_setup(cloud, s)
            d.cloudflare_setup(cloud, s)
        self.assertEqual(cloud.records[0], original)
        self.assertEqual(len(cloud.records), 2)
        self.assertFalse(any(m == 'POST' and p == '/zones' for m, p, _ in cloud.calls))
        self.assertTrue(any(m == 'POST' and p.endswith('/dns_records') for m, p, _ in cloud.calls))

    def test_uninstall_preserves_other_records_and_rules(self):
        cloud, s = Cloud(), state()
        cloud.node()
        for op in d.cf_uninstall_plan(cloud, s):
            cloud.api(*op)
        self.assertEqual([r['id'] for r in cloud.records], ['main'])
        self.assertEqual([r['id'] for r in cloud.rules], ['other'])
        self.assertEqual(cloud.settings['ssl'], 'full')
        self.assertFalse(any(m == 'DELETE' and p == '/zones/zone' for m, p, _ in cloud.calls))
        self.assertEqual(d.cf_uninstall_plan(cloud, s), [])  # Resume is harmless.

    def test_restore_preexisting_node_dns(self):
        cloud, s = Cloud(), state()
        cloud.node()
        s['dns_before'] = [{'type': 'A', 'name': s['host'], 'content': '192.0.2.20', 'ttl': 300, 'proxied': False}]
        for op in d.cf_uninstall_plan(cloud, s):
            cloud.api(*op)
        node = next(r for r in cloud.records if r['name'] == s['host'])
        self.assertEqual(node['content'], '192.0.2.20')
        self.assertFalse(node['proxied'])
        self.assertEqual(d.cf_uninstall_plan(cloud, s), [])

    def test_changed_dns_stops_before_mutation(self):
        cloud, s = Cloud(), state()
        cloud.node()
        cloud.records[-1]['content'] = '192.0.2.20'
        with self.assertRaises(d.Failure):
            d.cf_uninstall_plan(cloud, s)
        self.assertTrue(all(c[0] == 'GET' for c in cloud.calls))

    def test_changed_zone_setting_stops_before_mutation(self):
        cloud, s = Cloud(), state()
        cloud.node()
        cloud.settings['ssl'] = 'flexible'
        with self.assertRaises(d.Failure):
            d.cf_uninstall_plan(cloud, s)
        self.assertTrue(all(c[0] == 'GET' for c in cloud.calls))

    def test_missing_token_permission_does_not_skip_cloud_cleanup(self):
        with patch.object(d.CF, 'api', side_effect=d.APIError(403, 'denied')):
            with self.assertRaises(d.APIError):
                d.cf_uninstall_plan(d.CF('fake'), state())

    def test_never_touched_cache_rule_is_not_deleted(self):
        cloud, s = Cloud(), state()
        cloud.node()
        s.pop('cache_started')
        for op in d.cf_uninstall_plan(cloud, s):
            cloud.api(*op)
        self.assertEqual(len(cloud.rules), 2)

    def test_only_new_packages_selected(self):
        s = state()
        s['packages_added'] = ['curl', 'nginx', 'qrencode']
        with patch.object(d, 'installed_packages', return_value=['base', 'curl', 'nginx', 'qrencode', 'later-app']), \
             patch.object(d, 'run', return_value='Remv nginx [1]\nPurg qrencode [1]'):
            self.assertEqual(d.package_removal_plan(s), ['nginx', 'qrencode'])

    def test_dependency_on_added_package_stops_purge(self):
        s = state()
        s['packages_added'] = ['nginx']
        with patch.object(d, 'installed_packages', return_value=['base', 'nginx', 'later-app']), \
             patch.object(d, 'run', return_value='Remv nginx [1]\nRemv later-app [1]'):
            with self.assertRaises(d.Failure):
                d.package_removal_plan(s)

    def test_legacy_state_and_arbitrary_paths_rejected(self):
        with self.assertRaises(d.Failure):
            d.local_uninstall_check({'schema': 1})
        s = state()
        s['owned_files']['/etc/passwd'] = 'fake'
        with self.assertRaises(d.Failure):
            d.local_uninstall_check(s)

    def test_changed_owned_file_is_preserved(self):
        s = state()
        with tempfile.TemporaryDirectory() as td, patch.object(d, 'ROOT', Path(td)):
            p = Path(td) / 'cloudflare.ini'
            p.write_text('new manual content')
            s['owned_files'][str(p)] = hashlib.sha256(b'old content').hexdigest()
            with self.assertRaises(d.Failure):
                d.local_uninstall_check(s)
            self.assertTrue(p.exists())

    def test_cloud_failure_precedes_service_removal(self):
        s = state()
        with patch.object(d, 'local_uninstall_check'), patch.object(d, 'package_removal_plan', return_value=[]), \
             patch.object(d, 'token_input', return_value='fake'), \
             patch.object(d, 'cf_uninstall_plan', side_effect=d.APIError(403, 'denied')), \
             patch.object(d, 'run') as run:
            with self.assertRaises(d.APIError):
                d.uninstall(s)
            run.assert_not_called()

    def test_successful_local_cleanup_removes_only_owned_files(self):
        s = state()
        s['cf_removed'] = True
        with tempfile.TemporaryDirectory() as td:
            root, out = Path(td) / 'state', Path(td) / 'nodes'
            root.mkdir()
            out.mkdir()
            credentials = root / 'cloudflare.ini'
            credentials.write_text('test token')
            own = out / 'XHTTP.txt'
            own.write_text('test node')
            other = out / 'my-other-file.txt'
            other.write_text('must survive')
            s['owned_files'] = {str(p): d.fingerprint(p) for p in (credentials, own)}
            with patch.object(d, 'ROOT', root), patch.object(d, 'STATE', root / 'state.json'), \
                 patch.object(d, 'OUT', out), patch.object(d, 'BIN', Path(td) / 'bin' / 'xray'), \
                 patch.object(d, 'run', return_value=''), patch.object(d, 'package_removal_plan', return_value=[]), \
                 patch('builtins.input', return_value='UNINSTALL'):
                d.dump(d.STATE, s)
                d.uninstall(s)
                self.assertFalse(d.STATE.exists())
            self.assertFalse(credentials.exists())
            self.assertFalse(own.exists())
            self.assertEqual(other.read_text(), 'must survive')

    def test_reused_ufw_uninstall_restores_rules_without_disabling_firewall(self):
        s = state()
        s.update(cf_removed=True, reuse_ufw=True, ufw_was_active=True,
                 ufw_before={'/etc/ufw/user.rules': base64.b64encode(b'original SSH rules').decode()})
        with tempfile.TemporaryDirectory() as td, patch.object(d, 'ROOT', Path(td) / 'state'), \
             patch.object(d, 'STATE', Path(td) / 'state' / 'state.json'), \
             patch.object(d, 'OUT', Path(td) / 'nodes'), patch.object(d, 'BIN', Path(td) / 'bin' / 'xray'), \
             patch.object(d, 'local_uninstall_check'), patch.object(d, 'package_removal_plan', return_value=[]), \
             patch.object(d, 'write') as write, patch.object(d, 'run', return_value='') as run, \
             patch('builtins.input', return_value='UNINSTALL'):
            d.STATE.parent.mkdir()
            d.STATE.write_text('{}')
            d.uninstall(s)
        write.assert_any_call('/etc/ufw/user.rules', b'original SSH rules', 0o640)
        calls = [call.args for call in run.call_args_list if call.args[0] == 'ufw']
        self.assertEqual(calls, [('ufw', 'reload')])
        self.assertTrue(s['ufw_restored'])


if __name__ == '__main__':
    unittest.main()
