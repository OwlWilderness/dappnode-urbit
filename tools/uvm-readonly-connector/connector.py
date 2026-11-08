"""Fixed-target read-only status projection. No backend code is imported."""
import json
import http.client
import re
import ssl
import time

HOST = 'issue3-planet.public.dappnode.private'
PORT = 8443
PATH = '/api/status'
COOKIE_NAME = '__Host-import_session'
TIMEOUT = 5
MAX_RESPONSE = 65536

class Refused(Exception):
    """Only constant public messages may be attached to this exception."""


class Connector:
    """Operator construction only; no configuration is accepted from tool input.

    connection_factory is solely an offline test seam, never a tool argument.
    authorized is a fail-closed local latch, NOT a grant or policy override.
    """
    def __init__(self, *, context, session, authorized=False,
                 connection_factory=http.client.HTTPSConnection):
        if (not isinstance(context, ssl.SSLContext) or
                context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname):
            raise Refused('Verified HTTPS is required.')
        self._context = context
        self._session = session
        self._authorized = authorized is True
        self._factory = connection_factory

    def status(self):
        if not self._authorized:
            raise Refused('Live connection is disabled pending authorization.')
        conn = None
        try:
            # Recheck mutable context at the actual side-effect boundary.
            if self._context.verify_mode != ssl.CERT_REQUIRED or not self._context.check_hostname:
                raise Refused('Verified HTTPS is required.')
            sid = self._session()
            if type(sid) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{43}', sid):
                raise Refused('Dedicated owner session required.')
            deadline = time.monotonic() + TIMEOUT
            conn = self._factory(HOST, PORT, context=self._context, timeout=TIMEOUT)
            conn.request('GET', PATH, headers={'Accept': 'application/json',
                         'Host': HOST + ':' + str(PORT), 'Cookie': COOKIE_NAME + '=' + sid})
            sid = None
            response = conn.getresponse()
            if response.status == 401:
                raise Refused('Dedicated owner session expired or unavailable.')
            if response.status != 200:
                # Never follow redirects, reflect errors, or retry login/actions.
                raise Refused('Status request refused.')
            if response.getheader('Content-Type') != 'application/json':
                raise Refused('Invalid status response.')
            length = response.getheader('Content-Length')
            if (response.getheader('Transfer-Encoding') is not None or type(length) is not str or
                    not re.fullmatch(r'[0-9]{1,6}', length) or not 0 < int(length) <= MAX_RESPONSE):
                raise Refused('Invalid status response.')
            body = response.read(MAX_RESPONSE + 1)
            if len(body) != int(length) or time.monotonic() > deadline:
                raise Refused('Invalid status response.')
            return sanitize(body)
        except Refused:
            raise
        except Exception:
            raise Refused('Status transport unavailable.') from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def decode(raw):
    try:
        if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE:
            raise ValueError()
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(data) is not dict:
            raise ValueError()
        return data
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise Refused('Invalid status response.') from None


def sanitize(raw):
    data = decode(raw)
    def nested(name, key):
        value = data.get(name)
        return value.get(key) if type(value) is dict else None
    def enum(value, allowed):
        return value if type(value) is str and value in allowed else 'UNKNOWN'
    return {
        'manager': 'AUTHENTICATED_STATUS_RECEIVED',
        'ship_process': enum(nested('runtime', 'state'),
                             ('STOPPED', 'STARTING', 'RUNNING', 'FAULT', 'RECOVERY_REQUIRED')),
        'initialization': enum(nested('provisioning', 'state'), ('ATTEMPTED', 'COMPLETE')),
        'job_state': enum(nested('job', 'state'),
                          ('IDLE', 'LOCKED', 'UPLOADING', 'VALIDATING', 'COMMITTING',
                           'READY_LOCKED', 'RECOVERY_REQUIRED', 'FAILED')),
        'recovery_outcome': enum(nested('local_recovery', 'outcome'), ('PENDING', 'COMPLETE', 'REFUSED')),
        'recovery_reported_available': data.get('local_recovery_available') is True,
        'start_reported_available': data.get('start_available') is True,
        'ship_http_readiness': 'UNKNOWN_NOT_MEASURED',
    }
