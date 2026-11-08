"""Exact selection contract + descriptor assembly tests; no engines/ships."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]

class Assembly(unittest.TestCase):
    def test_explicit_selection_keeps_official_default_and_closes_candidate_context(self):
        script = ROOT/'build/assemble_planet.py'
        self.assertTrue(script.exists(), 'exact-baseline assembly missing')
        spec=importlib.util.spec_from_file_location('assembly', script)
        assembly=importlib.util.module_from_spec(spec); spec.loader.exec_module(assembly)
        recipe=assembly.dockerfile(ROOT)
        self.assertIn('58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698',recipe)
        self.assertIn('source-materials.tar.gz',recipe)
        self.assertIn('planet.py', recipe)
        self.assertIn('planet_service.py /opt/importer/managed_service.py',recipe)
        for component in ('boot_boundary.py','local_recovery.py','legacy_evidence.py','volume_guard.py'):
            self.assertIn(component,recipe)
        self.assertIn('--download', (ROOT/'build/Dockerfile').read_text())
        descriptors=assembly.descriptors(ROOT, '~sample-planet', 44444)
        self.assertEqual(descriptors['dappnode_package.json']['name'],'issue3-planet.public.dappnode.eth')
        compose=descriptors['docker-compose.yml']
        self.assertIn('planet_trial_data:/urbit',compose)
        self.assertIn('44444:34343/udp',compose)
        self.assertIn('URBIT_PUBLIC_SHIP_ORIGIN: ""', compose)
        enabled = assembly.descriptors(ROOT, '~sample-planet', 44444, 'https://ship.example.com')
        self.assertIn('URBIT_PUBLIC_SHIP_ORIGIN: "https://ship.example.com"', enabled['docker-compose.yml'])
        for origin in ('http://ship.example.com', 'https://ship.example.com:443',
                       'https://ship.example.com/path', 'https://user@ship.example.com'):
            with self.assertRaises(ValueError):
                assembly.descriptors(ROOT, '~sample-planet', 44444, origin)
        self.assertIn('"9444/tcp"', compose.split('    expose:', 1)[1])
        published = compose.split('    ports:', 1)[1].split('    expose:', 1)[0]
        self.assertEqual(published.strip(), '- "44444:34343/udp"')
        self.assertIn('EXPOSE 9444/tcp', recipe)
        self.assertIn('https://issue3-planet.public.dappnode.private:8443', compose)
        self.assertIn('https://ship.issue3-planet.public.dappnode.private:8443', compose)
        import sys
        sys.path.insert(0, str(ROOT/'tools/browser-importer'))
        from public_ingress import render_backend
        options = dict(tls_name='ship.issue3-planet.public.dappnode.private', bind='0.0.0.0',
                       port=9444, ship_port=8081, certificate='/synthetic/cert.pem',
                       key='/synthetic/key.pem', runtime_dir='/synthetic/run')
        config = render_backend(public_origin='https://ship.example.com', **options)
        self.assertEqual(config.count('proxy_pass '), 1)
        self.assertIn('proxy_pass http://127.0.0.1:8081;', config)
        self.assertNotIn(':8080', config)
        self.assertNotIn(':8443', config)
        self.assertIn('if ($http_host != "ship.example.com")', config)
        with self.assertRaises(ValueError):
            render_backend(public_origin='https://ship.example.com:443', **options)
        self.assertNotIn('pacfyl',compose)
        for identity,port in [('sample-planet',44444),('~sample-planet',34344),('~sample-planet',34343)]:
            with self.assertRaises(ValueError): assembly.descriptors(ROOT, identity,port)

    def test_public_origin_matches_backend_canonical_dns_without_explicit_port(self):
        import sys
        sys.path.insert(0, str(ROOT/'tools/browser-importer'))
        from package_service import parse_origin
        spec = importlib.util.spec_from_file_location('assembly', ROOT/'build/assemble_planet.py')
        assembly = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(assembly)
        max_host = '.'.join(('a'*63, 'b'*63, 'c'*63, 'd'*61))
        accepted = ('ship.example.com', 'my--ship.example.com', 'a.b',
                    'a'*63 + '.com', max_host, '127.0.0.1.example')
        refused = ('a', '127.0.0.1', 'a'*64 + '.com', max_host + 'd',
                   '-ship.example.com', 'ship-.example.com', 'ship..example.com',
                   'ship.example.com.', '.ship.example.com', 'Ship.example.com',
                   'ship_name.example.com', 'shíp.example.com')
        for host in accepted:
            origin = 'https://' + host
            with self.subTest(accepted=origin):
                self.assertEqual(parse_origin(origin, 443).value, origin)
                assets = assembly.descriptors(ROOT, '~sample-planet', 44444, origin)
                self.assertIn('URBIT_PUBLIC_SHIP_ORIGIN: "' + origin + '"',
                              assets['docker-compose.yml'])
        invalid_origins = tuple('https://' + host for host in refused) + (
            'http://ship.example.com', 'https://ship.example.com/path',
            'https://ship.example.com/', 'https://ship.example.com?query',
            'https://ship.example.com#fragment', 'https://user@ship.example.com',
            'https://[::1]', ' https://ship.example.com', 'https://ship.example.com\n')
        for origin in invalid_origins:
            with self.subTest(refused=origin):
                with self.assertRaises(ValueError):
                    parse_origin(origin, 443)
                with self.assertRaises(ValueError):
                    assembly.descriptors(ROOT, '~sample-planet', 44444, origin)
        # The consumer permits a matching explicit port; assembly deliberately does not.
        self.assertEqual(parse_origin('https://ship.example.com:443', 443).host,
                         'ship.example.com')
        for port in ('443', '8443', '0443', ''):
            with self.subTest(explicit_port=port):
                with self.assertRaises(ValueError):
                    assembly.descriptors(ROOT, '~sample-planet', 44444,
                                         'https://ship.example.com:' + port)

    def test_selected_adapter_hashes_exact_elf_and_suppresses_creation_io(self):
        import os
        import sys
        import subprocess
        from unittest.mock import patch
        sys.path.insert(0,str(ROOT/'tools/browser-importer'))
        import runtime
        selected = os.environ.get('UVM_PLANET_ARTIFACT_ROOT')
        if not selected: self.skipTest('set UVM_PLANET_ARTIFACT_ROOT for exact-artifact integration')
        artifact=Path(selected)/'urbit'
        self.assertTrue(artifact.is_file(), 'explicit artifact input is missing')
        real_open=os.open
        def opened(path,*args,**kwargs):
            return real_open(artifact if path=='/bin/urbit' else path,*args,**kwargs)
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryFile() as key:
            key.write(b'synthetic-secret'); key.flush(); key.seek(0)
            fd=real_open(tmp,os.O_RDONLY|os.O_DIRECTORY)
            try:
                with patch.object(runtime.os,'open',side_effect=opened), patch.object(runtime.sys,'platform','linux'), patch.object(runtime.subprocess,'Popen') as popen:
                    runtime.UpdatedRuntimeAdapter().create(fd,'~sample-planet',key.fileno())
                    args, options=popen.call_args
                    argv=args[0]
                    self.assertEqual(argv[argv.index('-w')+1],'sample-planet')
                    self.assertEqual(argv[argv.index('-k')+1],f'/proc/self/fd/{key.fileno()}')
                    self.assertIn('-x',argv); self.assertIn('-c',argv)
                    self.assertNotIn('synthetic-secret',str(popen.call_args))
                    self.assertEqual(options['stdout'],subprocess.DEVNULL)
                    self.assertEqual(options['stderr'],subprocess.DEVNULL)
                    self.assertEqual(options['stdin'],subprocess.DEVNULL)
                    self.assertFalse(options['shell'])
                    self.assertIn(key.fileno(),options['pass_fds'])
                    popen.reset_mock()
                    with self.assertRaises(runtime.ImportError): runtime.OfficialRuntimeAdapter().launch(fd)
                    popen.assert_not_called()
            finally: os.close(fd)

    def test_real_retained_inputs_authenticate_without_execution(self):
        script=ROOT/'build/assemble_planet.py'
        self.assertTrue(script.exists(), 'exact-baseline assembly missing')
        spec=importlib.util.spec_from_file_location('assembly',script)
        assembly=importlib.util.module_from_spec(spec); spec.loader.exec_module(assembly)
        selected = os.environ.get('UVM_PLANET_ARTIFACT_ROOT')
        if not selected: self.skipTest('set UVM_PLANET_ARTIFACT_ROOT for exact-artifact integration')
        artifact=Path(selected)
        self.assertTrue(artifact.is_dir(), 'explicit artifact root is missing')
        verified=assembly.verify_inputs(artifact)
        self.assertEqual(verified['urbit']['bytes'],42399776)
        with tempfile.TemporaryDirectory() as tmp:
            bad=Path(tmp)/'urbit'; bad.write_bytes(b'not-the-selected-baseline')
            with self.assertRaises(ValueError): assembly.verify_inputs(Path(tmp))
        # Disposable assembly only: synthetic public target/port are descriptor
        # fixtures, not an allocation, selected owner identity or ship launch.
        with tempfile.TemporaryDirectory() as tmp:
            output = assembly.assemble(ROOT, artifact, Path(tmp)/'fixture-context', '~sample-planet',44444)
            self.assertTrue((output/'assembly.json').is_file())
            self.assertEqual(assembly.digest(output/'context/candidate/urbit'), assembly.INPUTS['urbit'][1])
            self.assertTrue((output/'context/candidate/notices/openssl-3.5.9/LICENSE.txt').is_file())
            self.assertEqual((output/'context/tools/browser-importer/runtime.py').read_bytes(),
                             (ROOT/'tools/browser-importer/runtime.py').read_bytes())
            self.assertIn('from planet import PlanetImporter',
                (output/'context/tools/browser-importer/planet_service.py').read_text())
            self.assertIn('issue3-planet.public.dappnode.private', (output/'setup-wizard.yaml').read_text())
            with self.assertRaises(FileExistsError):
                assembly.assemble(ROOT, artifact, output, '~sample-planet',44444)

if __name__=='__main__': unittest.main(verbosity=2)
