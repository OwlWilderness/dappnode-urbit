"""Package entrypoint: authenticated import and explicit official-runtime start.

Unlike server.py's standalone importer, this entrypoint owns the runtime lifecycle.
Starting this service never launches Vere; start is a separate authenticated action.
"""
from runtime import ManagedImporter, OfficialRuntimeAdapter, OwnedChildScope
import sys
from server import main as serve


def production_engine(*args, **kwargs):
    # server.main calls this after synchronous TLS helpers/enrollment, before
    # creating any HTTP/import worker. No other process launch is permitted after
    # prepare; archive extraction is in-process. Enrollment never owns a writer.
    scope = OwnedChildScope.prepare() if sys.platform.startswith('linux') else None
    return ManagedImporter(*args, runtime_adapter=OfficialRuntimeAdapter(scope=scope), **kwargs)


def main():
    return serve(engine_class=production_engine)


if __name__ == '__main__':
    raise SystemExit(main())
