"""Minimal stdio MCP tools server; no listening socket, login, or mutations.

Protocol references and activation prerequisites are in README.md.
"""
import json
import os
import sys
from connector import Refused, decode

MAX_MESSAGE = 16384
VERSIONS = ('2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05')
TOOL = {
    'name': 'uvm_status',
    'description': ('Read sanitized UVM process/initialization/recovery observations. '
                    'Not ship health. HTTP readiness is unmeasured. No lifecycle actions.'),
    'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False},
    'annotations': {'readOnlyHint': True, 'destructiveHint': False,
                    'idempotentHint': True, 'openWorldHint': False},
}


class Protocol:
    def __init__(self, read_status):
        self.read_status = read_status
        self.initialized = False
        self.ready = False

    def handle(self, message):
        # Integer IDs only: sufficient for the intended SDK client; arbitrary
        # strings are never reflected into agent-visible output.
        rid = message.get('id') if type(message) is dict else None
        if type(rid) is not int or not -(2**53) < rid < 2**53:
            rid = None
        def error(code=-32602, text='Request rejected.'):
            return {'jsonrpc': '2.0', 'id': rid, 'error': {'code': code, 'message': text}}
        def result(value):
            return {'jsonrpc': '2.0', 'id': rid, 'result': value}
        if type(message) is not dict or message.get('jsonrpc') != '2.0':
            return error(-32600)
        method = message.get('method')
        params = message.get('params', {})
        if 'id' not in message:
            if method == 'notifications/initialized' and self.initialized and params == {}:
                self.ready = True
            # No notification can invoke read_status.
            return None
        if rid is None or type(params) is not dict:
            return error()
        if method == 'ping' and params == {}:
            return result({})
        if method == 'initialize' and not self.initialized:
            if (type(params.get('protocolVersion')) is not str or
                    type(params.get('capabilities')) is not dict or
                    type(params.get('clientInfo')) is not dict):
                return error()
            version = params['protocolVersion']
            self.initialized = True
            return result({'protocolVersion': version if version in VERSIONS else VERSIONS[0],
                           'capabilities': {'tools': {'listChanged': False}},
                           'serverInfo': {'name': 'uvm-readonly-connector', 'version': '0.1.0'}})
        if not self.ready:
            return error(-32000, 'Initialize the connector first.')
        if method == 'tools/list' and params == {}:
            return result({'tools': [TOOL]})
        if method == 'tools/call':
            if (set(params) != {'name', 'arguments'} or params['name'] != 'uvm_status' or
                    type(params['arguments']) is not dict or params['arguments'] != {}):
                return error()
            try:
                value = self.read_status()
                return result({'content': [{'type': 'text', 'text': json.dumps(value, separators=(',', ':'))}],
                               'isError': False})
            except Exception:
                # No raw HTTP errors, response bodies, paths, cookies or tracebacks.
                return result({'content': [{'type': 'text', 'text': 'Status unavailable; check authorized connection and dedicated session locally.'}],
                               'isError': True})
        return error(-32601, 'Method not available.')


def configured_status():
    # Gate BEFORE CA/session files are opened. This local latch is not permission
    # to bypass a guard: independent supported-route authorization is mandatory.
    if os.environ.get('UVM_CONNECTOR_ENABLE') != 'approved-status-only':
        raise Refused('Live connection is disabled pending authorization.')
    from credentials import load_context, read_session
    from connector import Connector
    ca = os.environ.get('UVM_CONNECTOR_PUBLIC_CA_FILE', '')
    session_file = os.environ.get('UVM_CONNECTOR_SESSION_FILE', '')
    return Connector(context=load_context(ca), session=lambda: read_session(session_file),
                     authorized=True).status()


def serve(source, sink, protocol):
    while True:
        line = source.readline(MAX_MESSAGE + 1)
        if not line:
            return 0
        if len(line) > MAX_MESSAGE or not line.endswith(b'\n'):
            # Fail closed instead of treating the tail as another message.
            return 2
        try:
            message = decode(line)
            response = protocol.handle(message)
        except Exception:
            response = {'jsonrpc': '2.0', 'id': None,
                        'error': {'code': -32700, 'message': 'Invalid protocol message.'}}
        if response is not None:
            sink.write(json.dumps(response, separators=(',', ':')).encode() + b'\n')
            sink.flush()


if __name__ == '__main__':
    try:
        raise SystemExit(serve(sys.stdin.buffer, sys.stdout.buffer, Protocol(configured_status)))
    except (BrokenPipeError, KeyboardInterrupt):
        raise SystemExit(0)
