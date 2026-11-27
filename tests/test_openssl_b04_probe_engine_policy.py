"""Explicit owner-approved engine-managed provenance boundary, host only."""
import unittest
from unittest.mock import patch
from tools.issue3_crypto_tls_probe import outer, docker_transport
from tests.test_openssl_b04_probe_outer import fixture

class PolicyTests(unittest.TestCase):
    def test_host_transport_does_not_apply_target_uid_wide_process_limit(self):
        import tempfile,resource,sys,json
        from pathlib import Path
        from tools.issue3_crypto_tls_probe import supervisor
        with tempfile.TemporaryDirectory() as d:
            row=supervisor.capture((sys.executable,'-c','import resource,json; print(json.dumps(resource.getrlimit(resource.RLIMIT_NPROC)))'),Path(d)/'capture',supervisor.BUDGETS['compile'])
            self.assertEqual(row['returncode'],0)
            self.assertEqual(json.loads((Path(d)/'capture/stdout').read_text()),list(resource.getrlimit(resource.RLIMIT_NPROC)))
    def test_docker24_nonrecursive_bind_syntax_preserves_control(self):
        cmd=outer.command(fixture())
        mounts=[x for x in cmd if x.startswith('--mount=')]
        self.assertEqual(len(mounts),5)
        self.assertTrue(all('bind-nonrecursive=true' in x and 'bind-recursive=' not in x for x in mounts))
    def binding(self,p):
        return dict(kind='engine-managed-platform',engine_id=p['transport']['engine_id'],
                    endpoint=p['transport']['endpoint'],platform='linux/amd64',
                    emulator_identity_verified=False,provenance_limitation_accepted=True)
    def test_explicit_engine_managed_policy_admitted_without_emulator_claim(self):
        p=fixture(); p['amd64_execution_binding']=self.binding(p)
        outer.validate(p)
    def test_incomplete_or_false_policy_refused(self):
        p=fixture(); b=self.binding(p)
        for k in b:
            q=dict(b); q.pop(k); p['amd64_execution_binding']=q
            with self.subTest(k=k), self.assertRaises(ValueError): outer.validate(p)
        for k,v in [('engine_id','wrong'),('endpoint','unix:///wrong'),('emulator_identity_verified',True),('provenance_limitation_accepted',False)]:
            p['amd64_execution_binding']=dict(b,**{k:v})
            with self.subTest(k=k), self.assertRaises(ValueError): outer.validate(p)
    def test_real_identity_boundary_accepts_only_bound_daemon(self):
        import json,tempfile
        from pathlib import Path
        p=fixture(); p['amd64_execution_binding']=self.binding(p)
        with tempfile.TemporaryDirectory() as d:
            cli=docker_transport.DockerCLI(p,Path(d))
            daemon=dict(id='engine',arch='aarch64',os='linux',cgroup='2')
            image=dict(p['base'],volumes=None,onbuild=None)
            with patch.object(docker_transport.supervisor,'digest',return_value={'sha256':docker_transport.CLIENT_SHA}), patch.object(cli,'query',side_effect=[json.dumps(daemon),json.dumps(image)]):
                cli.identity(p)
            p['amd64_execution_binding']['engine_id']='other'
            with patch.object(docker_transport.supervisor,'digest',return_value={'sha256':docker_transport.CLIENT_SHA}), patch.object(cli,'query',return_value=json.dumps(daemon)), self.assertRaises(ValueError):
                cli.identity(p)
