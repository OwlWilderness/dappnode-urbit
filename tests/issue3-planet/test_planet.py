"""Focused source-only fresh-planet slice. Never executes Vere."""
import os
import sys
import json
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/browser-importer'))
import runtime
from importer import Importer, ImportError

class Planet(unittest.TestCase):
    def test_fresh_creation_commits_stopped_without_automatic_resume(self):
        self.assertTrue(hasattr(runtime, 'UpdatedRuntimeAdapter'), 'exact-baseline adapter missing')
        import planet
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            paths = [Path(tmp) / n for n in ('pier', 'uploads', 'control')]
            for path in paths:
                path.mkdir(mode=0o700)
            class Adapter:
                launches = 0
                def create(self, pier_fd, identity, key_fd):
                    self.asserted = (identity, os.read(key_fd, 65536))
                    os.mkdir('ship', mode=0o700, dir_fd=pier_fd)
                    ship = os.open('ship', os.O_RDONLY | os.O_DIRECTORY, dir_fd=pier_fd)
                    try:
                        os.mkdir('.urb', mode=0o700, dir_fd=ship)
                    finally:
                        os.close(ship)
                    class Child:
                        def poll(self): return 0
                        def wait(self, timeout=None): return 0
                    return Child()
                def launch(self, fd):
                    self.launches += 1
                    raise AssertionError('no automatic resume')
            adapter = Adapter()
            manager = planet.PlanetImporter(*paths, planet_identity='~sample-planet', runtime_adapter=adapter)
            try:
                result = manager.provision(identity='~sample-planet', key=b'synthetic-private-key', confirmed_unused=True)
                manager.worker.join(5)
                self.assertFalse(manager.worker.is_alive())
                status = manager.status()
                self.assertEqual(status['provisioning']['state'], 'COMPLETE')
                self.assertEqual(status['job']['state'], 'READY_LOCKED')
                self.assertEqual(status['runtime'], {'state': 'STOPPED'})
                self.assertTrue(status['start_available'])
                self.assertEqual(adapter.asserted, ('~sample-planet', b'synthetic-private-key'))
                self.assertEqual(adapter.launches, 0)
                self.assertNotIn('synthetic-private-key', json.dumps(status))
                with self.assertRaises(ImportError):
                    manager.provision(identity='~sample-planet', key=b'synthetic-private-key', confirmed_unused=True)
            finally:
                manager.close()
            # Reopen through the production import-journal validator. Creation
            # has no archive and zero byte counts: it must still be an ordinary
            # durable READY_LOCKED job, never an automatic second creation/Start.
            before = {p.name: p.read_bytes() for p in paths[2].iterdir() if p.is_file()}
            reopened = planet.PlanetImporter(*paths, planet_identity='~sample-planet', runtime_adapter=adapter)
            try:
                status = reopened.status()
                self.assertEqual(status['provisioning']['state'], 'COMPLETE')
                self.assertEqual(status['job']['state'], 'READY_LOCKED')
                self.assertEqual(status['job']['total_bytes'], 0)
                self.assertEqual(status['runtime'], {'state': 'STOPPED'})
                self.assertTrue(status['start_available'])
                self.assertFalse(status['provision_available'])
                self.assertEqual(adapter.launches, 0)
                self.assertEqual(before, {p.name: p.read_bytes() for p in paths[2].iterdir() if p.is_file()})
            finally:
                reopened.close()

    def test_interrupted_creation_remains_fenced_across_reopen(self):
        import planet
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            paths = [Path(tmp) / n for n in ('pier', 'uploads', 'control')]
            for path in paths: path.mkdir(mode=0o700)
            class Adapter:
                calls = 0
                def create(self, *args):
                    self.calls += 1
                    raise RuntimeError('synthetic-private-key must not escape')
            adapter = Adapter()
            manager = planet.PlanetImporter(*paths, planet_identity='~sample-planet', runtime_adapter=adapter)
            manager.provision(identity='~sample-planet', key=b'synthetic-private-key', confirmed_unused=True)
            manager.worker.join(5)
            original = {p.name: p.read_bytes() for p in paths[2].iterdir() if p.is_file()}
            for operation in (lambda: manager.provision(identity='~sample-planet', key=b'x', confirmed_unused=True),
                              lambda: manager.create(total_bytes=1, expanded_limit=1, stopped=True),
                              lambda: manager.start(confirmed_stopped=True),
                              lambda: manager.recover(operation_id='b'*32)):
                with self.assertRaises(ImportError): operation()
            self.assertEqual(adapter.calls, 1)
            self.assertFalse(manager.status()['start_available'])
            manager.recovery_journal.close()
            Importer.close(manager)  # Fixture-only descriptor release, not settlement.
            reopened = planet.PlanetImporter(*paths, planet_identity='~sample-planet', runtime_adapter=adapter)
            try:
                self.assertFalse(reopened.status()['provision_available'])
                with self.assertRaises(ImportError):
                    reopened.provision(identity='~sample-planet', key=b'x', confirmed_unused=True)
                self.assertEqual(adapter.calls, 1)
                for name, data in original.items(): self.assertEqual((paths[2]/name).read_bytes(), data)
                self.assertNotIn(b'synthetic-private-key', b''.join(original.values()))
            finally:
                reopened.recovery_journal.close()
                Importer.close(reopened)

    def test_clean_exit_after_owner_stop_is_not_initialization_success(self):
        import planet
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            paths=[Path(tmp)/n for n in ('pier','uploads','control')]
            for path in paths: path.mkdir(mode=0o700)
            entered, released = threading.Event(), threading.Event()
            class Child:
                def poll(self): return 0 if released.is_set() else None
                def terminate(self): released.set()
                def wait(self, timeout=None):
                    if not released.wait(5): raise TimeoutError()
                    return 0
            class Adapter:
                def create(self, *args): entered.set(); return Child()
            manager=planet.PlanetImporter(*paths, planet_identity='~sample-planet',runtime_adapter=Adapter())
            try:
                manager.provision(identity='~sample-planet',key=b'synthetic-key',confirmed_unused=True)
                self.assertTrue(entered.wait(5))
                with self.assertRaises(ImportError): manager.stop()
                manager.worker.join(5)
                self.assertEqual(manager.status()['job']['state'],'RECOVERY_REQUIRED')
                self.assertEqual(manager.status()['provisioning']['state'],'ATTEMPTED')
                self.assertFalse(manager.status()['start_available'])
            finally:
                released.set()
                manager.worker.join(5)
                manager.recovery_journal.close(); Importer.close(manager)

    def test_native_completed_history_is_admitted_without_rewriting_evidence(self):
        import planet
        sys.path.insert(0,str(ROOT/'tests/issue20-upgrade'))
        from native_fixture import seed_native,snapshot
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            root=Path(tmp)
            for name in ('pier','uploads','control'): (root/name).mkdir(mode=0o700)
            (root/'pier/ship/.urb').mkdir(parents=True)
            job=dict(id='a'*32,state='READY_LOCKED',offset=9,total_bytes=9,expanded_limit=4096,expanded_bytes=32,files=1)
            (root/'control/job.json').write_text(json.dumps(job)); (root/'control/job.json').chmod(0o600)
            seed_native(root)
            before=snapshot(root)
            manager=planet.PlanetImporter(*(root/n for n in ('pier','uploads','control')),planet_identity='~sample-planet')
            try:
                self.assertEqual(manager.status()['runtime'],{'state':'RECOVERY_REQUIRED'})
                self.assertFalse(manager.status()['start_available'])
                after=snapshot(root)
                self.assertEqual({p:after[p] for p in before},before)
            finally:
                manager.recovery_journal.close(); Importer.close(manager)

class PrivateProvisionHTTP(unittest.TestCase):
    def test_authenticated_csrf_binary_key_intake_never_echoes_secret(self):
        import hashlib
        import http.client
        import server
        class Engine:
            calls = []
            fail = False
            def provision(self, **kwargs):
                self.calls.append(kwargs)
                if self.fail: raise RuntimeError(kwargs['key'].decode())
                return {'provisioning': {'state': 'ATTEMPTED'}}
        engine = Engine()
        salt = b'x' * 16
        credential = {'salt': salt.hex(), 'hash': hashlib.scrypt(b'fixture-password', salt=salt, n=16384, r=8, p=1).hex()}
        service = server.make_server(engine, ('127.0.0.1', 0), credential)
        thread = threading.Thread(target=service.serve_forever)
        thread.start()
        try:
            conn = http.client.HTTPConnection('127.0.0.1', service.server_port)
            headers = {'Origin': service.origin, 'Content-Type': 'application/octet-stream', 'X-Planet-Identity': '~sample-planet', 'X-Confirm-Unused': 'true'}
            secret = b'synthetic-key-never-reflect'
            def post(h):
                conn.request('POST', '/api/provision', secret, h)
                response = conn.getresponse()
                data = response.read()
                self.assertNotIn(secret, data)
                self.assertEqual(response.getheader('Cache-Control'), 'no-store')
                return response.status
            self.assertEqual(post(headers), 401)
            conn.request('POST', '/api/login', json.dumps({'password': 'fixture-password'}), {'Origin': service.origin, 'Content-Type': 'application/json'})
            response = conn.getresponse()
            cookie = response.getheader('Set-Cookie').split(';')[0]
            csrf = json.loads(response.read())['csrf']
            headers['Cookie'] = cookie
            self.assertEqual(post(headers), 403)
            self.assertEqual(engine.calls, [])
            headers['X-CSRF-Token'] = csrf
            self.assertEqual(post(headers), 202)
            self.assertEqual(engine.calls, [dict(identity='~sample-planet', key=secret, confirmed_unused=True)])
            engine.fail = True
            self.assertEqual(post(headers),409)
            headers['Origin'] = 'http://untrusted.invalid'
            self.assertEqual(post(headers),403)
            self.assertEqual(len(engine.calls),2)
            conn.close()
        finally:
            service.shutdown()
            service.server_close()
            thread.join(5)

if __name__ == '__main__':
    unittest.main(verbosity=2)
