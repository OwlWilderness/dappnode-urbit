"""Refuse an unfamiliar volume layout before the supervisor can write state.

Only directory metadata is inspected. No legacy pier/key payload is opened,
renamed, removed or automatically adopted.
"""

import os
import sys


def main(argv=None, *, root='/urbit'):
    try:
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with os.scandir(descriptor) as entries:
                layout = {entry.name: entry.is_dir(follow_symlinks=False) for entry in entries}
            if layout and (set(layout) != {'pier', 'uploads', 'control'} or not all(layout.values())):
                raise ValueError('unsupported layout')
            if not layout:
                # Establish the whole layout before pending certificate enrollment;
                # otherwise a first-run restart could see only control/ and refuse.
                for name in ('pier', 'uploads', 'control'):
                    os.mkdir(name, mode=0o700, dir_fd=descriptor)
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        print('VOLUME_LAYOUT_REFUSED: preserve the volume; follow the documented migration procedure.', file=sys.stderr)
        return 78
    args = sys.argv[1:] if argv is None else argv
    os.execv(sys.executable, [sys.executable, '/opt/importer/package_service.py', *args])


if __name__ == '__main__':
    sys.exit(main())
