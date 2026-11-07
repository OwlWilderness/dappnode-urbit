"""Package entrypoint: authenticated import and explicit official-runtime start.

Unlike server.py's standalone importer, this entrypoint owns the runtime lifecycle.
Starting this service never launches Vere; start is a separate authenticated action.
"""
from native_file_channel import main


if __name__ == '__main__':
    raise SystemExit(main())
