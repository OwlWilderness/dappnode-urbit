"""External controller HTTPS endpoint; no Docker socket in the worker.

An embedding authorized controller process supplies NativeController(NativeRPC,
real_lifecycle_bridge). No bridge implementation is fabricated here. Stock manager
routes lack that bridge; this module is runnable with an actual supplied backend,
and refuses startup without it. Server certificates/keys are supplied by operator
provisioning, not generated or acquired from any user's browser/profile.
"""
import json
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from permanent_recovery import BUILD, MissingNativeBridge, digest

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        self.connection.settimeout(10)
        try:
            cert=self.connection.getpeercert(binary_form=True)
            if not cert or digest(cert) not in self.server.client_fingerprints:
                raise ValueError()
            actions={'/legacy015/begin':'begin','/legacy015/check':'check','/legacy015/finish':'finish'}
            if self.path not in actions: raise ValueError()
            lengths=self.headers.get_all('Content-Length',[])
            if (len(lengths)!=1 or not lengths[0].isdecimal() or
                    not 0<int(lengths[0])<=16384 or self.headers.get('Transfer-Encoding') or
                    self.headers.get_all('Content-Type',[])!=['application/json']):
                raise ValueError()
            data=json.loads(self.rfile.read(int(lengths[0])))
            if (set(data)!={'nonce','build','tx','generation','paths','bindings','prior'} or
                    data['build']!=BUILD or not isinstance(data['nonce'],str) or len(data['nonce'])!=64):
                raise ValueError()
            nonce=data.pop('nonce');data.pop('build')
            result=self.server.controller.call(actions[self.path],data)
            body=json.dumps({**result,'nonce':nonce}).encode();status=200
        except Exception:
            body=b'{"error":"Native controller refused; maintenance remains fenced."}';status=409
        self.send_response(status);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store')
        self.end_headers();self.wfile.write(body)

def make_controller_server(controller, bind, tls_context, client_fingerprints):
    controller.require_bridge()
    if tls_context.verify_mode!=ssl.CERT_REQUIRED or not client_fingerprints:
        raise MissingNativeBridge('Mutual TLS and pinned worker client certificate required.')
    server=HTTPServer(bind,Handler)
    server.controller=controller
    server.client_fingerprints=frozenset(client_fingerprints)
    server.socket=tls_context.wrap_socket(server.socket,server_side=True)
    return server
