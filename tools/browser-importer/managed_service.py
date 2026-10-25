"""Package entrypoint: authenticated import and explicit official-runtime start.

Unlike server.py's standalone importer, this entrypoint owns the runtime lifecycle.
Starting this service never launches Vere; start is a separate authenticated action.
"""
from runtime import ManagedImporter
from server import main as serve


def main():
    return serve(engine_class=ManagedImporter)


if __name__ == '__main__':
    raise SystemExit(main())
